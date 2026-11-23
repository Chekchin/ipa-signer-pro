from flask import Flask, render_template, request, jsonify, send_from_directory, Response
import os
import time
import threading
import uuid
import subprocess
import platform
import zipfile
import plistlib
import glob
import shutil
import tarfile
import tempfile

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
OUTPUT_FOLDER = os.path.join(BASE_DIR, 'output')
PRESET_FOLDER = os.path.join(BASE_DIR, 'preloaded')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(PRESET_FOLDER, exist_ok=True)

EXPIRY_SECONDS = 3600  # 1 hour expiry for generated links and signed files
CLEANUP_INTERVAL_SECONDS = 60

SIGN_PROGRESS = {"percent": 0.0, "status": "idle", "message": ""}
JOB_PROGRESS = {}
LATEST_JOB_ID = None
JOB_METADATA = {}
JOB_TIMESTAMPS = {}
DATA_LOCK = threading.Lock()


def _set_progress(job_id, percent, status, message, extra=None):
    global SIGN_PROGRESS, LATEST_JOB_ID
    payload = {
        "job_id": job_id,
        "percent": percent,
        "status": status,
        "message": message,
        "updated_at": time.time(),
    }
    if extra:
        payload.update(extra)
    with DATA_LOCK:
        JOB_PROGRESS[job_id] = payload
        LATEST_JOB_ID = job_id
        SIGN_PROGRESS = {k: v for k, v in payload.items() if k != "updated_at"}


def _is_binary_compatible_with_os(binary_path):
    if not binary_path or not os.path.isfile(binary_path):
        return False
    try:
        with open(binary_path, "rb") as f:
            magic = f.read(4)
    except OSError:
        return False

    sys_name = platform.system()
    is_elf = (magic == b"\x7fELF")
    macho_magics = {
        b"\xfe\xed\xfa\xce",
        b"\xce\xfa\xed\xfe",
        b"\xfe\xed\xfa\xcf",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\xbe\xba\xfe\xca",
        b"\xca\xfe\xba\xbf",
        b"\xbf\xba\xfe\xca",
    }
    is_macho = (magic in macho_magics)

    if sys_name == "Darwin":
        return is_macho
    if sys_name == "Linux":
        return is_elf
    if sys_name == "Windows":
        return magic[:2] == b"MZ"
    return True


def _resolve_zsign_executable():
    sys_name = platform.system()
    if sys_name == "Windows":
        local_win = os.path.join(BASE_DIR, "zsign.exe")
        if _is_binary_compatible_with_os(local_win):
            return local_win
    else:
        local_zsign = os.path.join(BASE_DIR, "zsign")
        if _is_binary_compatible_with_os(local_zsign):
            try:
                os.chmod(local_zsign, 0o755)
            except Exception:
                pass
            return local_zsign

        os_specific = os.path.join(BASE_DIR, "zsign_mac" if sys_name == "Darwin" else "zsign_linux")
        if _is_binary_compatible_with_os(os_specific):
            try:
                os.chmod(os_specific, 0o755)
            except Exception:
                pass
            return os_specific

    search_paths = [
        shutil.which("zsign"),
        "/opt/homebrew/bin/zsign",
        "/usr/local/bin/zsign",
        "/usr/bin/zsign",
        os.path.expanduser("~/bin/zsign"),
    ]
    for candidate in search_paths:
        if candidate and _is_binary_compatible_with_os(candidate):
            return candidate

    if sys_name == "Darwin":
        raise Exception("រកមិនឃើញ zsign សម្រាប់ macOS ទេ។ សូមដំឡើងតាម Terminal: brew install zsign")
    raise Exception("រកមិនឃើញ zsign សម្រាប់ Linux ទេ សូមពិនិត្យហ្វាល់ zsign ក្នុង Folder ឬដំឡើងលើ Server។")


def _copy_large_file(src_path, dst_path, buffer_size=8 * 1024 * 1024):
    with open(src_path, "rb") as f_src, open(dst_path, "wb") as f_dst:
        shutil.copyfileobj(f_src, f_dst, length=buffer_size)


def _extract_dylib_from_deb(deb_path, work_dir):
    """Extract .dylib file(s) from a .deb archive if provided."""
    extracted_dylibs = []
    extract_dir = os.path.join(work_dir, "deb_extract")
    os.makedirs(extract_dir, exist_ok=True)
    with open(deb_path, "rb") as f:
        header = f.read(8)
        if header != b"!<arch>\n":
            return extracted_dylibs
        while True:
            entry_header = f.read(60)
            if len(entry_header) < 60:
                break
            name = entry_header[:16].decode("utf-8", errors="ignore").strip()
            size_str = entry_header[48:58].decode("utf-8", errors="ignore").strip()
            if not size_str.isdigit():
                break
            size = int(size_str)
            data = f.read(size)
            if size % 2 == 1:
                f.read(1)
            if name.startswith("data.tar"):
                tar_path = os.path.join(extract_dir, name.rstrip("/"))
                with open(tar_path, "wb") as tf:
                    tf.write(data)
                with tarfile.open(tar_path, "r:*") as tar:
                    tar.extractall(path=extract_dir)
                for root, _, files in os.walk(extract_dir):
                    for fn in files:
                        if fn.endswith(".dylib"):
                            extracted_dylibs.append(os.path.join(root, fn))
                break
    return extracted_dylibs


def _modify_ipa_before_sign(
    ipa_path,
    custom_version="",
    custom_icon_path=None,
    enable_file_sharing=False,
    remove_device_limit=False,
):
    """
    Apply Info.plist edits (version, file sharing, device limit) and optional custom icon
    into a modified IPA archive before running zsign.
    """
    needs_patch = bool(
        custom_version
        or (custom_icon_path and os.path.exists(custom_icon_path))
        or enable_file_sharing
        or remove_device_limit
    )
    if not needs_patch:
        return ipa_path, None

    temp_dir = tempfile.mkdtemp(prefix="ipa_patch_")
    patched_ipa = os.path.join(temp_dir, "patched.ipa")
    custom_icon_bytes = None
    if custom_icon_path and os.path.exists(custom_icon_path):
        with open(custom_icon_path, "rb") as f_ic:
            custom_icon_bytes = f_ic.read()

    with zipfile.ZipFile(ipa_path, "r") as zin:
        app_dir = ""
        info_plist_entry = ""
        plist_data = {}
        for name in zin.namelist():
            if name.startswith("Payload/") and name.endswith(".app/Info.plist") and name.count("/") == 2:
                info_plist_entry = name
                app_dir = name.rsplit("Info.plist", 1)[0]
                with zin.open(name) as pf:
                    plist_data = plistlib.load(pf)
                break

        if custom_version:
            plist_data["CFBundleShortVersionString"] = custom_version
            plist_data["CFBundleVersion"] = custom_version

        if enable_file_sharing:
            plist_data["UIFileSharingEnabled"] = True
            plist_data["LSSupportsOpeningDocumentsInPlace"] = True

        if remove_device_limit and "UISupportedDevices" in plist_data:
            plist_data.pop("UISupportedDevices", None)

        icon_targets = set()
        if custom_icon_bytes and app_dir:
            for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
                primary = plist_data.get(key, {}).get("CFBundlePrimaryIcon", {})
                for ic_prefix in primary.get("CFBundleIconFiles", []):
                    for item in zin.namelist():
                        if item.startswith(app_dir) and ic_prefix in os.path.basename(item) and item.lower().endswith(".png"):
                            icon_targets.add(item)
            for item in zin.namelist():
                if item.startswith(app_dir) and "AppIcon" in os.path.basename(item) and item.lower().endswith(".png"):
                    icon_targets.add(item)

        with zipfile.ZipFile(patched_ipa, "w", compression=zipfile.ZIP_DEFLATED) as zout:
            for item in zin.infolist():
                if item.filename == info_plist_entry and info_plist_entry:
                    zout.writestr(item, plistlib.dumps(plist_data))
                elif item.filename in icon_targets and custom_icon_bytes:
                    zout.writestr(item, custom_icon_bytes)
                else:
                    zout.writestr(item, zin.read(item.filename))

    return patched_ipa, temp_dir


def _extract_job_id_from_filename(filename):
    if filename.startswith("signed_"):
        parts = filename.split("_", 2)
        if len(parts) >= 3 and parts[1]:
            return parts[1]
    return None


def _is_expired(job_id, filepath=None):
    now = time.time()
    with DATA_LOCK:
        created = JOB_TIMESTAMPS.get(job_id)
    if created is not None:
        return (now - created) >= EXPIRY_SECONDS
    if filepath and os.path.exists(filepath):
        try:
            return (now - os.path.getmtime(filepath)) >= EXPIRY_SECONDS
        except OSError:
            return True
    return False


def _delete_expired_job(job_id):
    for pattern in (
        os.path.join(OUTPUT_FOLDER, f"signed_{job_id}_*"),
        os.path.join(OUTPUT_FOLDER, f"icon_{job_id}.*"),
        os.path.join(UPLOAD_FOLDER, f"{job_id}_*"),
    ):
        for path in glob.glob(pattern):
            try:
                if os.path.isfile(path):
                    os.remove(path)
                elif os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
            except Exception as e:
                print("Cleanup error:", e)
    with DATA_LOCK:
        JOB_METADATA.pop(job_id, None)
        JOB_TIMESTAMPS.pop(job_id, None)
        JOB_PROGRESS.pop(job_id, None)


def _cleanup_loop():
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        try:
            now = time.time()
            expired_ids = set()
            with DATA_LOCK:
                for jid, ts in list(JOB_TIMESTAMPS.items()):
                    if (now - ts) >= EXPIRY_SECONDS:
                        expired_ids.add(jid)

            for folder in (OUTPUT_FOLDER, UPLOAD_FOLDER):
                if not os.path.exists(folder):
                    continue
                for fname in os.listdir(folder):
                    fpath = os.path.join(folder, fname)
                    if not os.path.isfile(fpath):
                        continue
                    try:
                        if (now - os.path.getmtime(fpath)) >= EXPIRY_SECONDS:
                            if fname.startswith("signed_"):
                                jid = _extract_job_id_from_filename(fname)
                                if jid:
                                    expired_ids.add(jid)
                                else:
                                    os.remove(fpath)
                            elif fname.startswith("icon_"):
                                jid = fname.rsplit(".", 1)[0].replace("icon_", "", 1)
                                if jid:
                                    expired_ids.add(jid)
                                else:
                                    os.remove(fpath)
                            else:
                                os.remove(fpath)
                    except Exception as e:
                        print("Scan cleanup error:", e)

            for jid in expired_ids:
                _delete_expired_job(jid)
        except Exception as e:
            print("Cleanup loop error:", e)


threading.Thread(target=_cleanup_loop, daemon=True).start()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/progress')
def get_progress():
    job_id = request.args.get('job_id', '').strip()
    with DATA_LOCK:
        if job_id and job_id in JOB_PROGRESS:
            return jsonify({k: v for k, v in JOB_PROGRESS[job_id].items() if k != "updated_at"})
        if LATEST_JOB_ID and LATEST_JOB_ID in JOB_PROGRESS:
            return jsonify({k: v for k, v in JOB_PROGRESS[LATEST_JOB_ID].items() if k != "updated_at"})
        return jsonify(SIGN_PROGRESS)


@app.route('/output/<path:filename>')
def download_file(filename):
    filepath = os.path.join(OUTPUT_FOLDER, filename)
    jid = _extract_job_id_from_filename(filename)
    if jid and _is_expired(jid, filepath):
        _delete_expired_job(jid)
        return jsonify({"status": "error", "message": "Link ផុតកំណត់ 1 ម៉ោងហើយ និងហ្វាល់ត្រូវបានលុបស្វ័យប្រវត្តិ។"}), 410
    return send_from_directory(OUTPUT_FOLDER, filename, as_attachment=True)


@app.route('/preset-ipas')
def get_preset_ipas():
    ipas = []
    if os.path.exists(PRESET_FOLDER):
        for f in os.listdir(PRESET_FOLDER):
            if f.endswith('.ipa'):
                ipas.append(f)
    return jsonify({"status": "success", "ipas": ipas})


@app.route('/job-info')
def get_job_info():
    job_id = request.args.get('job_id', '')
    if job_id and _is_expired(job_id):
        _delete_expired_job(job_id)
        return jsonify({"status": "error", "message": "Job expired after 1 hour"}), 410

    with DATA_LOCK:
        meta = JOB_METADATA.get(job_id)
    if meta:
        return jsonify({"status": "success", **meta})

    pattern = os.path.join(OUTPUT_FOLDER, f"signed_{job_id}_*.ipa")
    matches = glob.glob(pattern)
    if matches:
        found_file = os.path.basename(matches[0])
        clean_title = found_file.replace(f"signed_{job_id}_", "").rsplit('.', 1)[0]

        icon_filename = f"icon_{job_id}.png"
        icon_path = os.path.join(OUTPUT_FOLDER, icon_filename)
        icon_url = f"/output/{icon_filename}" if os.path.exists(icon_path) else None

        return jsonify({
            "status": "success",
            "bundle_id": "com.chek.app",
            "version": "1.0.0",
            "title": clean_title,
            "filename": found_file,
            "icon_url": icon_url
        })

    return jsonify({"status": "error", "message": "Job not found"}), 404


@app.route('/manifest.plist')
def get_manifest():
    job_id = request.args.get('job_id', '')
    ipa_url = request.args.get('url', '')

    if job_id and _is_expired(job_id):
        _delete_expired_job(job_id)
        return Response("Manifest expired after 1 hour.", status=410, mimetype='text/plain')

    if not ipa_url and job_id:
        pattern = os.path.join(OUTPUT_FOLDER, f"signed_{job_id}_*.ipa")
        matches = glob.glob(pattern)
        if matches:
            filename = os.path.basename(matches[0])
            scheme = 'https' if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https' else 'http'
            ipa_url = f"{scheme}://{request.host}/output/{filename}"

    if ipa_url.startswith('http://'):
        ipa_url = ipa_url.replace('http://', 'https://', 1)

    with DATA_LOCK:
        meta = dict(JOB_METADATA.get(job_id, {}))
    bundle_id = request.args.get('bundle_id', meta.get('bundle_id', 'com.chek.app'))
    app_title = request.args.get('title', meta.get('title', 'CHEK STORE App'))
    app_version = request.args.get('version', meta.get('version', '1.0.0'))

    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>items</key>
    <array>
        <dict>
            <key>assets</key>
            <array>
                <dict>
                    <key>kind</key>
                    <string>software-package</string>
                    <key>url</key>
                    <string>{ipa_url}</string>
                </dict>
            </array>
            <key>metadata</key>
            <dict>
                <key>bundle-identifier</key>
                <string>{bundle_id}</string>
                <key>bundle-version</key>
                <string>{app_version}</string>
                <key>kind</key>
                <string>software</string>
                <key>title</key>
                <string>{app_title}</string>
            </dict>
        </dict>
    </array>
</dict>
</plist>"""
    return Response(plist_content, mimetype='application/xml')


@app.route('/sign', methods=['POST'])
def sign_ipa():
    try:
        preset_ipa = request.form.get('preset_ipa', '').strip()
        job_id = str(uuid.uuid4())[:8]
        ipa_path = ""
        safe_ipa_name = ""

        if preset_ipa:
            source_preset_path = os.path.join(PRESET_FOLDER, preset_ipa)
            if not os.path.exists(source_preset_path):
                return jsonify({"status": "error", "message": "រកមិនឃើញហ្វាល IPA ស្រាប់នេះទេ!"}), 400
            safe_ipa_name = preset_ipa.replace(" ", "_")
            ipa_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{safe_ipa_name}")
            _copy_large_file(source_preset_path, ipa_path)
        else:
            if 'ipa_file' not in request.files or not request.files['ipa_file'].filename:
                return jsonify({"status": "error", "message": "សូមជ្រើសរើសហ្វាល IPA ឬជ្រើសរើស App ស្រាប់!"}), 400
            ipa = request.files['ipa_file']
            safe_ipa_name = ipa.filename.replace(" ", "_")
            ipa_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{safe_ipa_name}")
            ipa.save(ipa_path)

        p12 = request.files.get('p12_file')
        mobileprovision = request.files.get('mobileprovision_file')
        custom_icon = request.files.get('custom_icon_file')
        tweak_file = request.files.get('tweak_file')

        p12_password = request.form.get('p12_password', '')
        custom_bundle_id = request.form.get('bundle_id', '').strip()
        custom_app_name = request.form.get('app_name', '').strip()
        custom_app_version = request.form.get('app_version', '').strip()
        enable_file_sharing = request.form.get('enable_file_sharing') == 'on'
        remove_device_limit = request.form.get('remove_device_limit') == 'on'

        extracted_bundle_id = "com.chek.app"
        extracted_app_name = safe_ipa_name.rsplit('.', 1)[0]
        extracted_app_version = "1.0.0"
        icon_relative_path = None

        try:
            with zipfile.ZipFile(ipa_path, 'r') as z:
                app_payload_dir = ""
                plist_data = {}
                for filename in z.namelist():
                    if filename.startswith('Payload/') and filename.endswith('.app/Info.plist'):
                        app_payload_dir = filename.rsplit('Info.plist', 1)[0]
                        with z.open(filename) as plist_file:
                            plist_data = plistlib.load(plist_file)
                            extracted_bundle_id = plist_data.get('CFBundleIdentifier', extracted_bundle_id)
                            extracted_app_name = plist_data.get('CFBundleDisplayName', plist_data.get('CFBundleName', extracted_app_name))
                            extracted_app_version = plist_data.get('CFBundleShortVersionString', extracted_app_version)
                            break

                icons_dict = plist_data.get('CFBundleIcons', {}).get('CFBundlePrimaryIcon', {}).get('CFBundleIconFiles', [])
                if not icons_dict:
                    icons_dict = plist_data.get('CFBundleIconFiles', [])

                if icons_dict and app_payload_dir:
                    icon_name = icons_dict[-1]
                    for filename in z.namelist():
                        if filename.startswith(app_payload_dir) and (icon_name in filename) and filename.endswith(('.png', '.jpg')):
                            icon_data = z.read(filename)
                            icon_filename = f"icon_{job_id}.png"
                            icon_dest = os.path.join(OUTPUT_FOLDER, icon_filename)
                            with open(icon_dest, 'wb') as f_out:
                                f_out.write(icon_data)
                            icon_relative_path = f"/output/{icon_filename}"
                            break
        except Exception as e:
            print("Icon extraction error:", e)

        final_bundle_id = custom_bundle_id if custom_bundle_id else extracted_bundle_id
        final_app_name = custom_app_name if custom_app_name else extracted_app_name
        final_app_version = custom_app_version if custom_app_version else extracted_app_version

        p12_path = None
        prov_path = None
        custom_icon_path = None
        tweak_path = None

        if p12 and p12.filename:
            p12_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{p12.filename}")
            p12.save(p12_path)

        if mobileprovision and mobileprovision.filename:
            prov_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{mobileprovision.filename}")
            mobileprovision.save(prov_path)

        if custom_icon and custom_icon.filename:
            custom_icon_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_icon_{custom_icon.filename}")
            custom_icon.save(custom_icon_path)
            icon_filename = f"icon_{job_id}.png"
            shutil.copyfile(custom_icon_path, os.path.join(OUTPUT_FOLDER, icon_filename))
            icon_relative_path = f"/output/{icon_filename}"

        if tweak_file and tweak_file.filename:
            tweak_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{tweak_file.filename}")
            tweak_file.save(tweak_path)

        _set_progress(job_id, 15.0, "processing", "កំពុងរៀបចំ Sign...")

        def run_signing(current_job_id):
            patch_temp_dir = None
            deb_temp_dir = None
            try:
                out_filename = f"signed_{current_job_id}_{safe_ipa_name}"
                output_path = os.path.join(OUTPUT_FOLDER, out_filename)

                with DATA_LOCK:
                    JOB_METADATA[current_job_id] = {
                        "bundle_id": final_bundle_id,
                        "title": final_app_name,
                        "version": final_app_version,
                        "filename": out_filename,
                        "icon_url": icon_relative_path
                    }
                    JOB_TIMESTAMPS[current_job_id] = time.time()

                _set_progress(current_job_id, 30.0, "processing", "កំពុងកែសម្រួលព័ត៌មាន App (Version / Icon / Info.plist)...")

                target_ipa_for_zsign, patch_temp_dir = _modify_ipa_before_sign(
                    ipa_path=ipa_path,
                    custom_version=custom_app_version,
                    custom_icon_path=custom_icon_path,
                    enable_file_sharing=enable_file_sharing,
                    remove_device_limit=remove_device_limit,
                )

                _set_progress(current_job_id, 55.0, "processing", "កំពុង Sign ហ្វាល IPA តាមរយៈ zsign Engine...")

                zsign_executable = _resolve_zsign_executable()

                cmd = [zsign_executable, "-f"]
                if p12_path:
                    cmd.extend(["-k", p12_path])
                if p12_password:
                    cmd.extend(["-p", p12_password])
                if prov_path:
                    cmd.extend(["-m", prov_path])
                if final_bundle_id:
                    cmd.extend(["-b", final_bundle_id])
                if final_app_name:
                    cmd.extend(["-n", final_app_name])

                if tweak_path:
                    if tweak_path.lower().endswith(".dylib"):
                        cmd.extend(["-l", tweak_path])
                    elif tweak_path.lower().endswith(".deb"):
                        deb_temp_dir = tempfile.mkdtemp(prefix="deb_work_")
                        dylibs = _extract_dylib_from_deb(tweak_path, deb_temp_dir)
                        for dl in dylibs:
                            cmd.extend(["-l", dl])

                cmd.extend(["-o", output_path, target_ipa_for_zsign])

                process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                if process.returncode != 0:
                    raise Exception(f"Sign Error: {process.stderr.strip() or process.stdout.strip()}")

                with DATA_LOCK:
                    JOB_TIMESTAMPS[current_job_id] = time.time()

                _set_progress(
                    current_job_id,
                    100.0,
                    "done",
                    "Sign ជោគជ័យដោយសុវត្ថិភាព!",
                    extra={"filename": out_filename, "job_id": current_job_id}
                )

            except Exception as e:
                _set_progress(current_job_id, 0.0, "error", str(e))
                _delete_expired_job(current_job_id)
            finally:
                for tmp_file in (ipa_path, p12_path, prov_path, custom_icon_path, tweak_path):
                    if tmp_file and os.path.exists(tmp_file):
                        try:
                            os.remove(tmp_file)
                        except Exception:
                            pass
                for tmp_d in (patch_temp_dir, deb_temp_dir):
                    if tmp_d and os.path.exists(tmp_d):
                        shutil.rmtree(tmp_d, ignore_errors=True)

        threading.Thread(target=run_signing, args=(job_id,), daemon=True).start()
        return jsonify({"status": "success", "message": "Started processing", "job_id": job_id})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8889))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
