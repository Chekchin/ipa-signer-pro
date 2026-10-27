from flask import Flask, render_template, request, jsonify, send_from_directory, Response, make_response, redirect
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
import urllib.parse

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
OUTPUT_FOLDER = os.path.join(BASE_DIR, 'output')
PRESET_FOLDER = os.path.join(BASE_DIR, 'preloaded')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)
os.makedirs(PRESET_FOLDER, exist_ok=True)

SIGN_PROGRESS = {"percent": 0.0, "status": "idle", "message": ""}
JOB_METADATA = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/progress')
def get_progress():
    return jsonify(SIGN_PROGRESS)

@app.route('/output/<path:filename>')
def download_file(filename):
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
            "title": clean_title,
            "filename": found_file,
            "icon_url": icon_url
        })

    return jsonify({"status": "error", "message": "Job not found"}), 404

@app.route('/manifest.plist')
def get_manifest():
    job_id = request.args.get('job_id', '')
    ipa_url = request.args.get('url', '')
    
    if not ipa_url and job_id:
        pattern = os.path.join(OUTPUT_FOLDER, f"signed_{job_id}_*.ipa")
        matches = glob.glob(pattern)
        if matches:
            filename = os.path.basename(matches[0])
            scheme = 'https' if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https' else 'http'
            ipa_url = f"{scheme}://{request.host}/output/{filename}"

    if ipa_url.startswith('http://'):
        ipa_url = ipa_url.replace('http://', 'https://', 1)

    meta = JOB_METADATA.get(job_id, {})
    bundle_id = request.args.get('bundle_id', meta.get('bundle_id', 'com.chek.app'))
    app_title = request.args.get('title', meta.get('title', 'CHEK STORE App'))

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
                <string>1.0.0</string>
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
    global SIGN_PROGRESS, JOB_METADATA
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
            shutil.copy(source_preset_path, ipa_path)
        else:
            if 'ipa_file' not in request.files or not request.files['ipa_file'].filename:
                return jsonify({"status": "error", "message": "សូមជ្រើសរើសហ្វាល IPA ឬជ្រើសរើស App ស្រាប់!"}), 400
            ipa = request.files['ipa_file']
            safe_ipa_name = ipa.filename.replace(" ", "_")
            ipa_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{safe_ipa_name}")
            ipa.save(ipa_path)

        p12 = request.files.get('p12_file')
        mobileprovision = request.files.get('mobileprovision_file')
        p12_password = request.form.get('p12_password', '')
        custom_bundle_id = request.form.get('bundle_id', '').strip()
        custom_app_name = request.form.get('app_name', '').strip()

        extracted_bundle_id = "com.chek.app"
        extracted_app_name = safe_ipa_name.rsplit('.', 1)[0]
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

        p12_path = None
        prov_path = None

        if p12 and p12.filename:
            p12_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{p12.filename}")
            p12.save(p12_path)

        if mobileprovision and mobileprovision.filename:
            prov_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{mobileprovision.filename}")
            mobileprovision.save(prov_path)

        SIGN_PROGRESS = {"percent": 15.0, "status": "processing", "message": "កំពុងរៀបចំ Sign..."}

        def run_signing():
            global SIGN_PROGRESS
            try:
                out_filename = f"signed_{job_id}_{safe_ipa_name}"
                output_path = os.path.join(OUTPUT_FOLDER, out_filename)

                JOB_METADATA[job_id] = {
                    "bundle_id": final_bundle_id,
                    "title": final_app_name,
                    "filename": out_filename,
                    "icon_url": icon_relative_path
                }

                SIGN_PROGRESS = {"percent": 40.0, "status": "processing", "message": "កំពុង Sign ហ្វាល IPA តាមរយៈ zsign Engine..."}

                zsign_executable = "zsign"
                local_zsign = os.path.join(BASE_DIR, "zsign")
                if os.path.exists(local_zsign):
                    zsign_executable = local_zsign
                    try:
                        os.chmod(zsign_executable, 0o755)
                    except Exception:
                        pass
                elif platform.system() == "Windows":
                    local_zsign_win = os.path.join(BASE_DIR, "zsign.exe")
                    if os.path.exists(local_zsign_win):
                        zsign_executable = local_zsign_win

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

                cmd.extend(["-o", output_path, ipa_path])

                process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                if process.returncode != 0:
                    raise Exception(f"Sign Error: {process.stderr.strip() or process.stdout.strip()}")

                SIGN_PROGRESS = {"percent": 100.0, "status": "done", "message": "Sign ជោគជ័យដោយសុវត្ថិភាព!", "filename": out_filename, "job_id": job_id}

            except Exception as e:
                SIGN_PROGRESS = {"percent": 0.0, "status": "error", "message": str(e)}
            finally:
                if os.path.exists(ipa_path):
                    os.remove(ipa_path)
                if p12_path and os.path.exists(p12_path):
                    os.remove(p12_path)
                if prov_path and os.path.exists(prov_path):
                    os.remove(prov_path)

        threading.Thread(target=run_signing).start()
        return jsonify({"status": "success", "message": "Started processing"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- មុខងារ UDID Finder ---
@app.route('/udid')
def udid_page():
    return render_template('udid.html')

@app.route('/profile.mobileconfig')
def download_profile():
    domain = request.host
    scheme = "https" if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https' else "http"
    server_url = f"{scheme}://{domain}"

    profile_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <dict>
        <key>URL</key>
        <string>{server_url}/udid-receive</string>
        <key>DeviceAttributes</key>
        <array>
            <string>UDID</string>
            <string>VERSION</string>
            <string>PRODUCT</string>
            <string>DEVICE_NAME</string>
        </array>
    </dict>
    <key>PayloadOrganization</key>
    <string>CHEK STORE UDID Finder</string>
    <key>PayloadDisplayName</key>
    <string>CHEK STORE UDID Profile</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadUUID</key>
    <string>A1B2C3D4-E5F6-7890-ABCD-EF0123456789</string>
    <key>PayloadIdentifier</key>
    <string>com.chekstore.profile</string>
    <key>PayloadType</key>
    <string>Profile Service</string>
</dict>
</plist>"""
    response = make_response(profile_content)
    response.headers['Content-Type'] = 'application/x-apple-aspen-config'
    response.headers['Content-Disposition'] = 'attachment; filename="chek_udid.mobileconfig"'
    return response

@app.route('/udid-receive', methods=['POST'])
def udid_receive():
    try:
        data = request.data
        plist_data = plistlib.loads(data)
        udid = plist_data.get('UDID', 'Unknown')
        device_name = plist_data.get('DEVICE_NAME', 'iPhone/iPad')
        return redirect(f"/udid?udid={udid}&name={urllib.parse.quote(device_name)}")
    except Exception as e:
        return f"Error processing UDID: {str(e)}", 400

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 8889))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)