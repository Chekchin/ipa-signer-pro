import html
import json
import os
import plistlib
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    send_from_directory,
    abort,
)
from werkzeug.utils import secure_filename

app = Flask(__name__)

# ==================== CONFIG & SECURITY ====================
MAX_IPA_SIZE_BYTES = 5 * 1024 * 1024 * 1024  # 5 GB
app.config["MAX_CONTENT_LENGTH"] = MAX_IPA_SIZE_BYTES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
PRELOAD_DIRS = [
    os.path.join(BASE_DIR, "preloaded"),
    os.path.join(BASE_DIR, "preset_ipas"),
    os.path.join(BASE_DIR, "presets"),
]
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMP_WORK_DIR = "/tmp/chek_signer_work"
KEYS_VAULT_FILE = os.path.join(BASE_DIR, "keys_vault.json")

ONE_HOUR_SECONDS = 3600
CLEANUP_INTERVAL_SECONDS = 60
ADMIN_KEY = os.environ.get("CHEK_ADMIN_KEY", "")
ADMIN_TELEGRAM_URL = os.environ.get("CHEK_ADMIN_TELEGRAM", "https://t.me/chinchek55")
KEY_SERVER_VERIFY_URL = os.environ.get(
    "KEY_SERVER_VERIFY_URL", "https://get-key-all-chek.fly.dev/api/keys/verify"
)
ZSIGN_BIN = os.environ.get("ZSIGN_BIN", shutil.which("zsign") or "zsign")

for d in (UPLOAD_DIR, OUTPUT_DIR, STATIC_DIR, TEMP_WORK_DIR, PRELOAD_DIRS[0]):
    os.makedirs(d, exist_ok=True)

jobs_lock = threading.Lock()
jobs = {}

keys_lock = threading.Lock()


def is_safe_path(base_dir: str, target_path: str) -> bool:
    base_real = os.path.realpath(base_dir)
    target_real = os.path.realpath(target_path)
    return target_real == base_real or target_real.startswith(base_real + os.sep)


def safe_name(filename: str, fallback: str = "file.bin") -> str:
    cleaned = secure_filename(os.path.basename(filename or ""))
    return cleaned if cleaned else fallback


def resolve_zsign_binary() -> str:
    env_bin = (os.environ.get("ZSIGN_BIN") or ZSIGN_BIN or "").strip()
    candidates = []
    if env_bin:
        candidates.append(env_bin)
        if not os.path.isabs(env_bin):
            candidates.append(os.path.join(BASE_DIR, env_bin))

    candidates.extend([
        os.path.join(BASE_DIR, "zsign"),
        os.path.join(BASE_DIR, "bin", "zsign"),
        "/usr/local/bin/zsign",
        "/usr/bin/zsign",
        shutil.which("zsign") or "",
    ])

    for cand in candidates:
        if not cand:
            continue
        found = shutil.which(cand) if os.path.sep not in cand else cand
        if found and os.path.isfile(found):
            if not os.access(found, os.X_OK):
                try:
                    os.chmod(found, 0o755)
                except Exception:
                    pass
            if os.access(found, os.X_OK):
                return found

    return env_bin or "zsign"


# ==================== KEY VAULT STORAGE & VERIFICATION ====================
def _normalize_key_record(raw: dict) -> dict:
    if not isinstance(raw, dict):
        return {}
    key_str = str(raw.get("key") or "").strip()
    if not key_str:
        return {}
    try:
        max_dev = max(1, int(raw.get("maxDevices", raw.get("max_devices", 1)) or 1))
    except Exception:
        max_dev = 1

    raw_devices = raw.get("boundDevices", raw.get("bound_devices", []))
    if not isinstance(raw_devices, list):
        raw_devices = []
    bound_devices = []
    for d in raw_devices:
        ds = str(d or "").strip()
        if ds and ds not in bound_devices:
            bound_devices.append(ds)
    if len(bound_devices) > max_dev:
        bound_devices = bound_devices[:max_dev]

    dur_ms_raw = raw.get("durationMs", raw.get("duration_ms"))
    duration_ms = None if dur_ms_raw is None else max(0, int(dur_ms_raw))

    activated_raw = raw.get("activatedAt", raw.get("activated_at"))
    activated_at = int(activated_raw) if activated_raw not in (None, "", 0) else None

    expires_raw = raw.get("expiresAt", raw.get("expires_at"))
    expires_at = int(expires_raw) if expires_raw not in (None, "", 0) else None

    created_raw = raw.get("createdAt", raw.get("created_at"))
    created_at = int(created_raw) if created_raw not in (None, "", 0) else int(time.time() * 1000)

    return {
        "key": key_str,
        "kind": str(raw.get("kind") or "game").strip().lower(),
        "kindLabel": str(raw.get("kindLabel") or raw.get("kind_label") or "Game").strip(),
        "targetName": str(raw.get("targetName") or raw.get("target_name") or "App").strip(),
        "owner": str(raw.get("owner") or "User").strip(),
        "durationLabel": str(raw.get("durationLabel") or raw.get("duration_label") or "Custom").strip(),
        "durationMs": duration_ms,
        "maxDevices": max_dev,
        "boundDevices": bound_devices,
        "createdAt": created_at,
        "activatedAt": activated_at,
        "expiresAt": expires_at,
        "paused": bool(raw.get("paused", False)),
    }


def load_keys_vault() -> list:
    with keys_lock:
        if not os.path.isfile(KEYS_VAULT_FILE):
            return []
        try:
            with open(KEYS_VAULT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                return []
            cleaned = []
            for item in data:
                norm = _normalize_key_record(item)
                if norm:
                    cleaned.append(norm)
            return cleaned
        except Exception:
            return []


def save_keys_vault(keys_list: list) -> list:
    normalized = []
    seen = set()
    for item in (keys_list or []):
        norm = _normalize_key_record(item)
        if norm and norm["key"] not in seen:
            seen.add(norm["key"])
            normalized.append(norm)

    with keys_lock:
        tmp_path = KEYS_VAULT_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(normalized, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, KEYS_VAULT_FILE)
    return normalized


def _extract_admin_key_from_request() -> str:
    header_key = (request.headers.get("X-Admin-Key") or "").strip()
    if header_key:
        return header_key
    body = request.get_json(silent=True)
    if isinstance(body, dict) and body.get("admin_key"):
        return str(body.get("admin_key")).strip()
    return (request.form.get("admin_key") or request.args.get("admin_key") or "").strip()


def evaluate_and_bind_key(key_value: str, device_id: str = "", target_name: str = "", bind_device: bool = True):
    """Validate key status (paused, expired, target, device limit) and optionally bind device_id."""
    clean_key = (key_value or "").strip()
    clean_dev = (device_id or "").strip()
    clean_target = (target_name or "").strip().lower()

    if not clean_key:
        return False, "MISSING_KEY", "សូមបញ្ចូល Key ជាមុនសិន។", None

    now_ms = int(time.time() * 1000)
    vault = load_keys_vault()
    matched_idx = None
    for idx, rec in enumerate(vault):
        if rec.get("key") == clean_key:
            matched_idx = idx
            break

    if matched_idx is None:
        return False, "INVALID_KEY", "Key មិនត្រឹមត្រូវ ឬមិនមានក្នុងប្រព័ន្ធទេ។", None

    rec = dict(vault[matched_idx])
    rec_target = str(rec.get("targetName") or "").strip().lower()
    if clean_target and rec_target and clean_target != rec_target:
        return (
            False,
            "WRONG_TARGET",
            f"Key នេះសម្រាប់តែ {rec.get('targetName')} ប៉ុណ្ណោះ មិនអាចប្រើលើ {target_name} បានទេ។",
            rec,
        )

    if rec.get("paused"):
        return False, "PAUSED_KEY", "Key នេះត្រូវបានផ្អាកដំណើរការជាបណ្តោះអាសន្ន។", rec

    expires_at = rec.get("expiresAt")
    if rec.get("activatedAt") and expires_at is not None and now_ms >= int(expires_at):
        return False, "EXPIRED_KEY", "Key នេះបានផុតកំណត់រយៈពេលប្រើប្រាស់ហើយ។", rec

    max_dev = max(1, int(rec.get("maxDevices") or 1))
    bound_devs = list(rec.get("boundDevices") or [])
    changed = False

    if clean_dev:
        if clean_dev in bound_devs:
            pass
        elif len(bound_devs) < max_dev:
            if bind_device:
                bound_devs.append(clean_dev)
                rec["boundDevices"] = bound_devs
                changed = True
        else:
            return (
                False,
                "DEVICE_LIMIT_REACHED",
                f"Key នេះកំណត់បានត្រឹមតែ {max_dev} Device ប៉ុណ្ណោះ (ពេញ {len(bound_devs)}/{max_dev} Device រួចហើយ)។",
                rec,
            )

    if bind_device and not rec.get("activatedAt"):
        rec["activatedAt"] = now_ms
        dur_ms = rec.get("durationMs")
        rec["expiresAt"] = (now_ms + int(dur_ms)) if dur_ms is not None else None
        changed = True

    if changed:
        vault[matched_idx] = rec
        save_keys_vault(vault)

    rem_ms = None
    if rec.get("expiresAt") is not None:
        rem_ms = max(0, int(rec["expiresAt"]) - now_ms)

    info = {
        "key": rec["key"],
        "owner": rec.get("owner"),
        "kind": rec.get("kind"),
        "targetName": rec.get("targetName"),
        "maxDevices": max_dev,
        "boundDevices": bound_devs,
        "activatedAt": rec.get("activatedAt"),
        "expiresAt": rec.get("expiresAt"),
        "remainingMs": rem_ms,
        "paused": bool(rec.get("paused", False)),
    }
    return True, "ACTIVE", "Key ត្រឹមត្រូវ និងកំពុងដំណើរការ។", info


def verify_key_remote_or_local(key_value: str, device_id: str = "", target_name: str = "", bind_device: bool = True):
    """Verify key against Fly.io key-admin first; fallback to local vault if unreachable."""
    clean_key = (key_value or "").strip()
    clean_dev = (device_id or "").strip()
    clean_target = (target_name or "").strip()

    if not clean_key:
        return False, "MISSING_KEY", "សូមបញ្ចូល Key ជាមុនសិន។", None

    try:
        import ssl

        ssl_ctx = None
        try:
            import certifi
            ssl_ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            ssl_ctx = ssl.create_default_context()

        payload = json.dumps({
            "key": clean_key,
            "device_id": clean_dev,
            "target_name": clean_target,
            "bind": bool(bind_device),
        }).encode("utf-8")

        req = urllib.request.Request(
            KEY_SERVER_VERIFY_URL,
            data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8, context=ssl_ctx) as resp:
            raw_body = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw_body) if raw_body else {}
            print("FLY VERIFY RESPONSE:", data)
            if isinstance(data, dict) and data.get("valid") is True:
                return (
                    True,
                    str(data.get("code") or "ACTIVE"),
                    str(data.get("message") or "Key ត្រឹមត្រូវ។"),
                    data.get("key_info"),
                )
            if isinstance(data, dict) and data.get("valid") is False:
                return (
                    False,
                    str(data.get("code") or "INVALID_KEY"),
                    str(data.get("message") or "Key មិនត្រឹមត្រូវទេ។"),
                    data.get("key_info"),
                )
    except urllib.error.HTTPError as he:
        try:
            err_raw = he.read().decode("utf-8", errors="replace")
            err_data = json.loads(err_raw) if err_raw else {}
            print("FLY VERIFY HTTP ERROR:", he.code, err_data)
            if isinstance(err_data, dict) and err_data.get("message"):
                return (
                    False,
                    str(err_data.get("code") or "INVALID_KEY"),
                    str(err_data.get("message")),
                    err_data.get("key_info"),
                )
        except Exception:
            pass
    except Exception as exc:
        print("FLY VERIFY EXCEPTION:", exc)

    return evaluate_and_bind_key(
        key_value=clean_key,
        device_id=clean_dev,
        target_name=clean_target,
        bind_device=bind_device,
    )


def sanitize_zip_member_path(member_name: str) -> str:
    """Sanitize zip member path for APFS/Linux so invalid chars never cause Errno 22."""
    normalized = (member_name or "").replace("\\", "/")
    parts = []
    for raw_part in normalized.split("/"):
        if not raw_part or raw_part in (".", ".."):
            continue
        cleaned = re.sub(r'[\x00-\x1f\x7f:"*?<>|]', "_", raw_part).strip()
        if cleaned and cleaned not in (".", ".."):
            parts.append(cleaned)
    return "/".join(parts)


def find_preload_ipa_path(requested_name: str):
    """Find matching .ipa file across preloaded / preset_ipas / presets folders safely."""
    clean_req = safe_name(requested_name, "")
    if not clean_req:
        return None
    for pdir in PRELOAD_DIRS:
        if not os.path.isdir(pdir):
            continue
        for fname in os.listdir(pdir):
            if not fname.lower().endswith(".ipa"):
                continue
            candidate = os.path.join(pdir, fname)
            if not is_safe_path(pdir, candidate) or not os.path.isfile(candidate):
                continue
            if fname == requested_name or fname == clean_req or safe_name(fname) == clean_req:
                return candidate
    return None


def list_preload_ipas():
    seen = set()
    result = []
    for pdir in PRELOAD_DIRS:
        if not os.path.isdir(pdir):
            continue
        for fname in sorted(os.listdir(pdir)):
            if not fname.lower().endswith(".ipa"):
                continue
            full = os.path.join(pdir, fname)
            if is_safe_path(pdir, full) and os.path.isfile(full) and fname not in seen:
                seen.add(fname)
                result.append(fname)
    return result


def strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m|\[[0-9;]*m", "", text or "")


def format_mb(num_bytes: int) -> str:
    return f"{max(0, num_bytes) / (1024 * 1024):.1f} MB"


def free_disk_bytes(path_to_check: str) -> int:
    try:
        target = path_to_check if os.path.exists(path_to_check) else "/"
        return shutil.disk_usage(target).free
    except Exception:
        return MAX_IPA_SIZE_BYTES


def permanent_meta_path(job_id: str) -> str:
    clean_id = safe_name(job_id, "job")
    return os.path.join(OUTPUT_DIR, f"meta_{clean_id}.json")


def save_permanent_job_if_needed(job_snapshot: dict):
    """Persist permanent retention job metadata to disk so links survive server restarts."""
    if not job_snapshot or job_snapshot.get("retention_mode") != "permanent":
        return
    if job_snapshot.get("status") != "done":
        return
    jid = safe_name(job_snapshot.get("job_id") or "")
    if not jid:
        return
    meta_file = permanent_meta_path(jid)
    if not is_safe_path(OUTPUT_DIR, meta_file):
        return
    payload = {
        "job_id": jid,
        "status": "done",
        "percent": 100,
        "message": job_snapshot.get("message") or "រួចរាល់",
        "retention_mode": "permanent",
        "created_at": job_snapshot.get("created_at") or time.time(),
        "filename": job_snapshot.get("filename") or "",
        "title": job_snapshot.get("title") or job_snapshot.get("app_name") or "App",
        "app_name": job_snapshot.get("app_name") or job_snapshot.get("title") or "App",
        "icon_url": job_snapshot.get("icon_url") or "/static/cheklogo.png",
    }
    try:
        with open(meta_file, "w", encoding="utf-8") as mf:
            json.dump(payload, mf, ensure_ascii=False, indent=2)
    except Exception:
        pass


def load_permanent_job(job_id: str):
    clean_id = safe_name(job_id, "")
    if not clean_id:
        return None
    meta_file = permanent_meta_path(clean_id)
    if not is_safe_path(OUTPUT_DIR, meta_file) or not os.path.isfile(meta_file):
        return None
    try:
        with open(meta_file, "r", encoding="utf-8") as mf:
            data = json.load(mf)
        if isinstance(data, dict) and data.get("retention_mode") == "permanent":
            return data
    except Exception:
        pass
    return None


def clear_active_temp_workspace(active_job_id: str = "", force_all_non_active: bool = False):
    """Clear temporary work/upload files when switching tabs or starting a new sign without touching output/."""
    now = time.time()

    try:
        for entry in os.listdir("/tmp"):
            if entry.startswith("zsign_folder_"):
                full_tmp = os.path.join("/tmp", entry)
                if os.path.isdir(full_tmp) and is_safe_path("/tmp", full_tmp):
                    try:
                        if force_all_non_active or (now - os.path.getmtime(full_tmp)) > 10:
                            shutil.rmtree(full_tmp, ignore_errors=True)
                    except Exception:
                        pass
    except Exception:
        pass

    try:
        for entry in os.listdir(TEMP_WORK_DIR):
            if active_job_id and entry == f"job_{active_job_id}":
                continue
            full_work = os.path.join(TEMP_WORK_DIR, entry)
            if is_safe_path(TEMP_WORK_DIR, full_work):
                shutil.rmtree(full_work, ignore_errors=True)
    except Exception:
        pass

    try:
        for fname in os.listdir(UPLOAD_DIR):
            if active_job_id and fname.startswith(f"{active_job_id}_"):
                continue
            fpath = os.path.join(UPLOAD_DIR, fname)
            if os.path.isfile(fpath) and is_safe_path(UPLOAD_DIR, fpath):
                if force_all_non_active or (now - os.path.getmtime(fpath)) > 120:
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass
    except Exception:
        pass


def purge_stale_temp_and_expired_files(active_job_id: str = ""):
    """Free disk space by cleaning leftover temp/uploads and expired 1h outputs (never touching permanent)."""
    clear_active_temp_workspace(active_job_id=active_job_id, force_all_non_active=False)

    now = time.time()
    expired_ids = []
    expired_snaps = []
    with jobs_lock:
        for jid, jdata in list(jobs.items()):
            if jid == active_job_id:
                continue
            if jdata.get("retention_mode", "1h") == "permanent":
                continue
            if (now - jdata.get("created_at", now)) >= ONE_HOUR_SECONDS:
                expired_ids.append(jid)
                expired_snaps.append(dict(jdata))
        for jid in expired_ids:
            jobs.pop(jid, None)

    for snap in expired_snaps:
        cleanup_job_artifacts(snap)


def update_job(job_id: str, **kwargs):
    snap_to_save = None
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id].update(kwargs)
            jobs[job_id]["updated_at"] = time.time()
            if jobs[job_id].get("retention_mode") == "permanent" and jobs[job_id].get("status") == "done":
                snap_to_save = {k: v for k, v in jobs[job_id].items() if k != "proc"}
    if snap_to_save:
        save_permanent_job_if_needed(snap_to_save)


def get_job(job_id: str):
    clean_id = safe_name(job_id, "")
    if not clean_id:
        return None
    with jobs_lock:
        if clean_id in jobs:
            return dict(jobs[clean_id])
    return load_permanent_job(clean_id)


def is_job_cancelled(job_id: str) -> bool:
    j = get_job(job_id)
    return bool(j and j.get("cancel_requested"))


def stream_save_upload(file_storage, dest_path: str, job_id: str, expected_total_bytes: int = 0):
    written = 0
    chunk_size = 1024 * 1024 * 4
    last_report_t = 0.0

    with open(dest_path, "wb") as out:
        while True:
            if is_job_cancelled(job_id):
                raise RuntimeError("Job cancelled during upload")
            chunk = file_storage.stream.read(chunk_size)
            if not chunk:
                break
            written += len(chunk)
            if written > MAX_IPA_SIZE_BYTES:
                raise ValueError("File exceeds maximum allowed size of 5GB")
            out.write(chunk)

            now = time.monotonic()
            if now - last_report_t >= 0.15:
                last_report_t = now
                if expected_total_bytes > 0:
                    pct = min(45.0, (written / expected_total_bytes) * 45.0)
                    msg = f"កំពុង Send ({format_mb(written)} / {format_mb(expected_total_bytes)})"
                else:
                    pct = min(45.0, 5.0 + (written / (1024 * 1024 * 200)) * 40.0)
                    msg = f"កំពុង Send ({format_mb(written)})"
                update_job(job_id, status="running", percent=round(pct, 2), message=msg)

    return written


def extract_ipa_metadata(ipa_path: str, job_work_dir: str, job_id: str):
    """Extract app name and icon image from IPA without failing signing if absent."""
    app_name = None
    icon_rel_url = None
    extract_dir = os.path.join(job_work_dir, "_meta_extract")
    try:
        os.makedirs(extract_dir, exist_ok=True)
        with zipfile.ZipFile(ipa_path, "r") as zf:
            payload_app = None
            for member in zf.namelist():
                if "__MACOSX/" in member:
                    continue
                m = re.match(r"^(Payload/[^/]+\.app)/Info\.plist$", member)
                if m:
                    payload_app = m.group(1)
                    zf.extract(member, extract_dir)
                    break

            if payload_app:
                app_name = os.path.basename(payload_app).replace(".app", "")
                plist_path = os.path.join(extract_dir, payload_app, "Info.plist")
                if os.path.exists(plist_path):
                    try:
                        xml_plist = plist_path + ".xml"
                        if shutil.which("plutil"):
                            subprocess.run(
                                ["plutil", "-convert", "xml1", "-o", xml_plist, plist_path],
                                check=False,
                                timeout=10,
                            )
                            target_plist = xml_plist if os.path.exists(xml_plist) else plist_path
                        else:
                            target_plist = plist_path

                        with open(target_plist, "rb") as pf:
                            raw_bytes = pf.read()

                        try:
                            pl = plistlib.loads(raw_bytes)
                            if isinstance(pl, dict):
                                found_name = (
                                    pl.get("CFBundleDisplayName")
                                    or pl.get("CFBundleName")
                                    or pl.get("CFBundleExecutable")
                                )
                                if isinstance(found_name, str) and found_name.strip():
                                    app_name = found_name.strip()
                        except Exception:
                            text_data = raw_bytes.decode("utf-8", errors="ignore")
                            m_disp = re.search(
                                r"<key>CFBundleDisplayName</key>\s*<string>([^<]+)</string>",
                                text_data,
                            )
                            m_name = re.search(
                                r"<key>CFBundleName</key>\s*<string>([^<]+)</string>",
                                text_data,
                            )
                            candidate = (m_disp.group(1) if m_disp else "") or (
                                m_name.group(1) if m_name else ""
                            )
                            if candidate.strip():
                                app_name = candidate.strip()
                    except Exception:
                        pass

                icon_candidates = [
                    n for n in zf.namelist()
                    if n.startswith(payload_app + "/")
                    and "__MACOSX/" not in n
                    and n.lower().endswith((".png", ".jpg", ".jpeg"))
                    and "icon" in os.path.basename(n).lower()
                ]
                if not icon_candidates:
                    icon_candidates = [
                        n for n in zf.namelist()
                        if n.startswith(payload_app + "/")
                        and "__MACOSX/" not in n
                        and n.lower().endswith((".png", ".jpg", ".jpeg"))
                    ]

                if icon_candidates:
                    best_icon = max(icon_candidates, key=lambda name: zf.getinfo(name).file_size)
                    zf.extract(best_icon, extract_dir)
                    extracted_file = os.path.join(extract_dir, best_icon)
                    if os.path.exists(extracted_file):
                        ext = os.path.splitext(extracted_file)[1].lower() or ".png"
                        out_icon_name = f"icon_{job_id}{ext}"
                        out_icon_path = os.path.join(OUTPUT_DIR, out_icon_name)
                        shutil.copy2(extracted_file, out_icon_path)
                        icon_rel_url = f"/output/{out_icon_name}"
    except Exception:
        pass
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)

    return app_name, icon_rel_url


def _extract_ipa_install_meta(ipa_file_path: str, fallback_title: str, fallback_id: str):
    bundle_id = f"com.chek.signed.{fallback_id}"
    bundle_version = "1.0"
    app_title = fallback_title or "Signed App"

    if ipa_file_path and os.path.isfile(ipa_file_path):
        try:
            with zipfile.ZipFile(ipa_file_path, "r") as zf:
                for member in zf.namelist():
                    if "__MACOSX/" in member:
                        continue
                    if re.match(r"^Payload/[^/]+\.app/Info\.plist$", member):
                        raw_plist = zf.read(member)
                        try:
                            pl = plistlib.loads(raw_plist)
                            if isinstance(pl, dict):
                                bid = pl.get("CFBundleIdentifier")
                                bver = pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion")
                                bname = pl.get("CFBundleDisplayName") or pl.get("CFBundleName")
                                if isinstance(bid, str) and bid.strip():
                                    bundle_id = bid.strip()
                                if bver is not None and str(bver).strip():
                                    bundle_version = str(bver).strip()
                                if isinstance(bname, str) and bname.strip() and not fallback_title:
                                    app_title = bname.strip()
                        except Exception:
                            pass
                        break
        except Exception:
            pass

    return bundle_id, bundle_version, app_title


def find_payload_dir(*search_roots):
    for root_dir in search_roots:
        if not root_dir or not os.path.exists(root_dir):
            continue
        for current, dirs, _ in os.walk(root_dir):
            dirs[:] = [d for d in dirs if d != "__MACOSX"]
            if "Payload" in dirs:
                candidate = os.path.join(current, "Payload")
                if os.path.isdir(candidate) and any(name.endswith(".app") for name in os.listdir(candidate)):
                    return candidate
    return None


def find_app_dir(payload_dir: str):
    if not payload_dir or not os.path.isdir(payload_dir):
        return None
    for name in os.listdir(payload_dir):
        if name.endswith(".app"):
            full = os.path.join(payload_dir, name)
            if os.path.isdir(full):
                return full
    return None


def patch_info_plist(app_dir: str, enable_file_sharing: bool = False, remove_device_limit: bool = False):
    """Apply Info.plist modifications for File Sharing (Files App) and Device Limit removal (iPad support)."""
    if not app_dir or (not enable_file_sharing and not remove_device_limit):
        return
    plist_path = os.path.join(app_dir, "Info.plist")
    if not os.path.isfile(plist_path):
        return
    try:
        with open(plist_path, "rb") as pf:
            pl_data = plistlib.load(pf)
        if not isinstance(pl_data, dict):
            return

        if enable_file_sharing:
            pl_data["UIFileSharingEnabled"] = True
            pl_data["LSSupportsOpeningDocumentsInPlace"] = True

        if remove_device_limit:
            pl_data.pop("UISupportedDevices", None)
            pl_data["UIDeviceFamily"] = [1, 2]

        with open(plist_path, "wb") as pf:
            plistlib.dump(pl_data, pf, fmt=plistlib.FMT_BINARY)
    except Exception as exc:
        print("PATCH INFO.PLIST WARNING:", exc)


def pre_extract_ipa(ipa_path: str, dest_extract_dir: str, job_id: str, total_bytes: int):
    """Unzip IPA into dest_extract_dir safely, handling invalid filename chars (Errno 22)."""
    os.makedirs(dest_extract_dir, exist_ok=True)
    last_t = 0.0

    needed_free = max(512 * 1024 * 1024, int(total_bytes * 2.1))
    avail_free = min(free_disk_bytes(dest_extract_dir), free_disk_bytes(OUTPUT_DIR))
    if avail_free < needed_free:
        raise OSError(
            f"[Errno 28] No space left on device (Free: {format_mb(avail_free)}, Needed ~{format_mb(needed_free)})."
        )

    try:
        with zipfile.ZipFile(ipa_path, "r") as zf:
            members = [m for m in zf.namelist() if "__MACOSX/" not in m and not m.endswith("/.DS_Store")]
            total_m = max(1, len(members))
            done_bytes = 0
            for idx, member in enumerate(members, start=1):
                if is_job_cancelled(job_id):
                    return False
                info = zf.getinfo(member)
                is_dir = member.endswith("/")
                safe_rel = sanitize_zip_member_path(member)
                if safe_rel:
                    out_target = os.path.join(dest_extract_dir, *safe_rel.split("/"))
                    if not is_safe_path(dest_extract_dir, out_target):
                        continue
                    try:
                        if is_dir:
                            os.makedirs(out_target, exist_ok=True)
                        else:
                            os.makedirs(os.path.dirname(out_target), exist_ok=True)
                            with zf.open(info, "r") as src_f, open(out_target, "wb") as dst_f:
                                shutil.copyfileobj(src_f, dst_f, length=1024 * 1024 * 2)
                    except OSError as oe:
                        if oe.errno == 28 or "No space left" in str(oe):
                            raise OSError("[Errno 28] No space left on device")
                        if oe.errno == 22:
                            continue
                        raise

                done_bytes += info.file_size
                now = time.monotonic()
                if now - last_t >= 0.25 or idx == total_m:
                    last_t = now
                    pct = 46.0 + min(1.0, idx / total_m) * 14.0
                    mb_now = min(total_bytes, done_bytes)
                    update_job(
                        job_id,
                        percent=round(pct, 2),
                        message=f"កំពុងត្រៀមហ្វាល IPA ({format_mb(mb_now)} / {format_mb(total_bytes)})",
                    )

        shutil.rmtree(os.path.join(dest_extract_dir, "__MACOSX"), ignore_errors=True)
        if find_payload_dir(dest_extract_dir):
            return True
    except OSError as oe:
        if oe.errno == 28 or "No space left" in str(oe):
            raise OSError("[Errno 28] No space left on device")
    except Exception:
        pass

    return False


def zip_payload_clean(final_ipa_path: str, job_id: str, total_bytes: int, *search_roots):
    """Zip signed Payload directory safely into final_ipa_path (skipping missing/transient files without failing)."""
    payload_dir = find_payload_dir(*search_roots)
    if not payload_dir or not os.path.isdir(payload_dir):
        return False

    parent_of_payload = os.path.dirname(payload_dir)
    os.makedirs(os.path.dirname(final_ipa_path), exist_ok=True)
    tmp_zip = final_ipa_path + ".tmp_zip"
    if os.path.exists(tmp_zip):
        try:
            os.remove(tmp_zip)
        except Exception:
            pass

    all_entries = []
    for root, dirs, files in os.walk(payload_dir):
        dirs[:] = [d for d in dirs if d != "__MACOSX"]
        for fname in files:
            if fname == ".DS_Store" or fname.startswith("._"):
                continue
            all_entries.append(os.path.join(root, fname))

    total_entries = max(1, len(all_entries))
    processed_bytes = 0
    last_t = 0.0

    try:
        with zipfile.ZipFile(tmp_zip, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
            for idx, full_p in enumerate(all_entries, start=1):
                if is_job_cancelled(job_id):
                    try:
                        os.remove(tmp_zip)
                    except Exception:
                        pass
                    return False

                try:
                    if not os.path.exists(full_p):
                        continue
                    if os.path.islink(full_p):
                        link_target = os.readlink(full_p)
                        rel_p = os.path.relpath(full_p, parent_of_payload)
                        zinfo = zipfile.ZipInfo(rel_p)
                        zinfo.create_system = 3
                        zinfo.external_attr = (0o120777 << 16)
                        zf.writestr(zinfo, link_target.encode("utf-8", errors="replace"))
                        continue

                    if not os.path.isfile(full_p):
                        continue

                    fsize = os.path.getsize(full_p)
                    rel_p = os.path.relpath(full_p, parent_of_payload)
                    zf.write(full_p, rel_p)
                    processed_bytes += fsize
                except FileNotFoundError:
                    continue
                except OSError as fe:
                    if fe.errno == 28 or "No space left" in str(fe):
                        raise
                    continue

                now = time.monotonic()
                if now - last_t >= 0.25 or idx == total_entries:
                    last_t = now
                    zip_ratio = min(1.0, idx / total_entries)
                    pct = 75.0 + zip_ratio * 23.0
                    mb_label = format_mb(processed_bytes if processed_bytes <= total_bytes else total_bytes)
                    update_job(
                        job_id,
                        percent=round(pct, 2),
                        message=f"កំពុងបញ្ចប់ IPA ({mb_label} / {format_mb(total_bytes)})",
                    )

        if os.path.exists(tmp_zip) and os.path.getsize(tmp_zip) > 0:
            os.replace(tmp_zip, final_ipa_path)
            return True
    except OSError as oe:
        try:
            if os.path.exists(tmp_zip):
                os.remove(tmp_zip)
        except Exception:
            pass
        if oe.errno == 28 or "No space left" in str(oe):
            raise OSError("[Errno 28] No space left on device")
        raise
    return False


def monitor_signing_progress(job_id: str, proc: subprocess.Popen, ipa_size: int):
    """Update real MB & percentage continuously while zsign is signing."""
    stop_flag = threading.Event()
    start_t = time.monotonic()

    def _poll():
        while not stop_flag.is_set() and proc.poll() is None:
            if is_job_cancelled(job_id):
                break
            elapsed = time.monotonic() - start_t
            est_ratio = min(1.0, elapsed / max(6.0, (ipa_size / (1024 * 1024 * 35.0)) + 5.0))
            pct = 60.0 + est_ratio * 28.0
            done_mb = min(ipa_size, int(ipa_size * est_ratio))
            update_job(
                job_id,
                percent=round(pct, 2),
                message=f"កំពុង Sign ({format_mb(done_mb)} / {format_mb(ipa_size)})",
            )
            stop_flag.wait(0.4)

    t = threading.Thread(target=_poll, daemon=True)
    t.start()
    return stop_flag, t


def run_zsign_cmd(job_id: str, base_args: list, target_arg: str, cwd_dir: str, ipa_size: int):
    zsign_cmd = resolve_zsign_binary()
    if not os.path.isfile(zsign_cmd) and shutil.which(zsign_cmd) is None:
        raise FileNotFoundError(
            f"[Errno 2] No such file or directory: '{zsign_cmd}' (សូមដំឡើង ឬដាក់ binary 'zsign' លើ server)"
        )
    cmd = [zsign_cmd] + base_args + [target_arg]
    proc = subprocess.Popen(
        cmd,
        cwd=cwd_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    with jobs_lock:
        if job_id in jobs:
            jobs[job_id]["proc"] = proc

    stop_flag, poll_thread = monitor_signing_progress(job_id, proc, ipa_size)

    output_lines = []
    try:
        while True:
            if is_job_cancelled(job_id):
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                return -1, []

            line = proc.stdout.readline() if proc.stdout else ""
            if not line and proc.poll() is not None:
                break
            if line:
                cleaned_line = strip_ansi(line).strip()
                if cleaned_line:
                    output_lines.append(cleaned_line)
    finally:
        stop_flag.set()
        poll_thread.join(timeout=1.5)
        with jobs_lock:
            if job_id in jobs:
                jobs[job_id].pop("proc", None)

    return proc.returncode, output_lines


def run_sign_worker(job_id: str, params: dict):
    work_dir = os.path.join(TEMP_WORK_DIR, f"job_{job_id}")
    os.makedirs(work_dir, exist_ok=True)
    update_job(job_id, work_dir=work_dir)

    ipa_src = params.get("ipa_path")
    p12_src = params.get("p12_path")
    prov_src = params.get("prov_path")
    custom_icon_path = params.get("custom_icon_path")
    tweak_path = params.get("tweak_path")
    enable_file_sharing = bool(params.get("enable_file_sharing", False))
    remove_device_limit = bool(params.get("remove_device_limit", False))
    delete_ipa_after_extract = bool(params.get("delete_ipa_after_extract", True))

    try:
        clear_active_temp_workspace(active_job_id=job_id, force_all_non_active=True)

        if is_job_cancelled(job_id):
            update_job(job_id, status="cancelled", percent=0, message="Cancelled")
            return

        p12_password = params.get("p12_password", "")
        custom_app_name = (params.get("app_name") or "").strip()
        custom_bundle_id = (params.get("bundle_id") or "").strip()
        custom_version = (params.get("app_version") or "").strip()

        ipa_size = os.path.getsize(ipa_src) if ipa_src and os.path.exists(ipa_src) else 0
        update_job(
            job_id,
            status="running",
            percent=46.0,
            message=f"កំពុងត្រួតពិនិត្យ IPA ({format_mb(ipa_size)})",
        )

        detected_name, detected_icon = extract_ipa_metadata(ipa_src, work_dir, job_id)
        final_title = custom_app_name or detected_name or "Signed App"
        final_icon_url = detected_icon

        if custom_icon_path and os.path.exists(custom_icon_path):
            icon_ext = os.path.splitext(custom_icon_path)[1].lower() or ".png"
            custom_icon_filename = f"icon_{job_id}{icon_ext}"
            shutil.copy2(custom_icon_path, os.path.join(OUTPUT_DIR, custom_icon_filename))
            final_icon_url = f"/output/{custom_icon_filename}"

        if is_job_cancelled(job_id):
            update_job(job_id, status="cancelled", percent=0, message="Cancelled")
            return

        out_filename = f"signed_{job_id}.ipa"
        out_ipa_path = os.path.join(OUTPUT_DIR, out_filename)
        zsign_work_dir = os.path.join(work_dir, "zsign_tmp")
        os.makedirs(zsign_work_dir, exist_ok=True)
        os.makedirs(os.path.dirname(out_ipa_path), exist_ok=True)
        shutil.rmtree(os.path.join(zsign_work_dir, "__MACOSX"), ignore_errors=True)

        pre_extracted = pre_extract_ipa(ipa_src, zsign_work_dir, job_id, ipa_size)
        if pre_extracted and delete_ipa_after_extract and ipa_src and os.path.exists(ipa_src) and is_safe_path(UPLOAD_DIR, ipa_src):
            try:
                os.remove(ipa_src)
                ipa_src = None
            except Exception:
                pass

        if is_job_cancelled(job_id):
            update_job(job_id, status="cancelled", percent=0, message="Cancelled")
            return

        extracted_app_dir = find_app_dir(find_payload_dir(zsign_work_dir)) if pre_extracted else None
        if extracted_app_dir:
            patch_info_plist(
                extracted_app_dir,
                enable_file_sharing=enable_file_sharing,
                remove_device_limit=remove_device_limit,
            )

        sign_target = extracted_app_dir if extracted_app_dir else ipa_src

        base_args = [
            "-k", p12_src,
            "-m", prov_src,
            "-z", "1",
        ]
        if not extracted_app_dir:
            base_args.extend(["-o", out_ipa_path])
        if p12_password:
            base_args.extend(["-p", p12_password])
        if custom_app_name:
            base_args.extend(["-n", custom_app_name])
        if custom_bundle_id:
            base_args.extend(["-b", custom_bundle_id])
        if custom_version:
            base_args.extend(["-v", custom_version])
        if custom_icon_path and os.path.exists(custom_icon_path):
            base_args.extend(["-i", custom_icon_path])
        if tweak_path and os.path.exists(tweak_path):
            base_args.extend(["-l", tweak_path])

        rc, output_lines = run_zsign_cmd(job_id, base_args, sign_target, zsign_work_dir, ipa_size)

        if is_job_cancelled(job_id):
            update_job(job_id, status="cancelled", percent=0, message="Cancelled")
            return

        combined_out = "\n".join(output_lines)
        if "No space left" in combined_out:
            raise OSError("[Errno 28] No space left on device")

        zip_ok = False
        if find_payload_dir(zsign_work_dir, work_dir) is not None:
            zip_ok = zip_payload_clean(out_ipa_path, job_id, ipa_size, zsign_work_dir, work_dir)
        elif rc == 0 and os.path.exists(out_ipa_path) and os.path.getsize(out_ipa_path) > 0:
            zip_ok = True

        shutil.rmtree(zsign_work_dir, ignore_errors=True)

        if is_job_cancelled(job_id):
            update_job(job_id, status="cancelled", percent=0, message="Cancelled")
            return

        if not zip_ok or not os.path.exists(out_ipa_path) or os.path.getsize(out_ipa_path) == 0:
            err_tail = "\n".join(output_lines[-4:]) if output_lines else f"zsign exited with code {rc}"
            update_job(job_id, status="error", percent=0, message=f"Sign Error: {err_tail}")
            return

        final_mb = format_mb(os.path.getsize(out_ipa_path))
        update_job(
            job_id,
            status="done",
            percent=100,
            message=f"រួចរាល់ ({final_mb})",
            filename=out_filename,
            title=final_title,
            app_name=final_title,
            icon_url=final_icon_url or "/static/cheklogo.png",
        )

    except Exception as exc:
        if is_job_cancelled(job_id):
            update_job(job_id, status="cancelled", percent=0, message="Cancelled")
        else:
            update_job(job_id, status="error", percent=0, message=str(exc))
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        if delete_ipa_after_extract and ipa_src and os.path.exists(ipa_src) and is_safe_path(UPLOAD_DIR, ipa_src):
            try:
                os.remove(ipa_src)
            except Exception:
                pass
        for temp_in in (p12_src, prov_src, custom_icon_path, tweak_path):
            if temp_in and os.path.exists(temp_in) and is_safe_path(UPLOAD_DIR, temp_in):
                try:
                    os.remove(temp_in)
                except Exception:
                    pass


def cleanup_job_artifacts(job_data: dict):
    job_id = job_data.get("job_id")
    work_dir = job_data.get("work_dir")
    if work_dir and os.path.exists(work_dir) and is_safe_path(TEMP_WORK_DIR, work_dir):
        shutil.rmtree(work_dir, ignore_errors=True)

    filename = job_data.get("filename")
    if filename:
        out_file = os.path.join(OUTPUT_DIR, safe_name(filename))
        if os.path.exists(out_file) and is_safe_path(OUTPUT_DIR, out_file):
            try:
                os.remove(out_file)
            except Exception:
                pass

    if job_id:
        for fname in os.listdir(UPLOAD_DIR):
            if fname.startswith(f"{job_id}_"):
                fpath = os.path.join(UPLOAD_DIR, fname)
                if os.path.exists(fpath) and is_safe_path(UPLOAD_DIR, fpath):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass

        for fname in os.listdir(OUTPUT_DIR):
            if fname.startswith(f"icon_{job_id}"):
                fpath = os.path.join(OUTPUT_DIR, fname)
                if os.path.exists(fpath) and is_safe_path(OUTPUT_DIR, fpath):
                    try:
                        os.remove(fpath)
                    except Exception:
                        pass

        meta_file = permanent_meta_path(job_id)
        if os.path.exists(meta_file) and is_safe_path(OUTPUT_DIR, meta_file):
            try:
                os.remove(meta_file)
            except Exception:
                pass


def retention_cleanup_loop():
    """Auto-delete 1h retention jobs/files; keep permanent retention jobs untouched."""
    while True:
        time.sleep(CLEANUP_INTERVAL_SECONDS)
        purge_stale_temp_and_expired_files()


cleanup_thread = threading.Thread(target=retention_cleanup_loop, daemon=True)
cleanup_thread.start()


# ==================== ROUTES ====================
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/key-vault")
def key_vault_page():
    return render_template("key_generator.html")


@app.route("/api/keys/sync", methods=["POST"])
def api_keys_sync():
    if not ADMIN_KEY:
        return jsonify({
            "status": "error",
            "code": "SERVER_CONFIG_ERROR",
            "message": "Server មិនទាន់បានកំណត់ CHEK_ADMIN_KEY ទេ។",
        }), 500

    provided_admin = _extract_admin_key_from_request()
    if not provided_admin or provided_admin != ADMIN_KEY:
        return jsonify({
            "status": "error",
            "code": "INVALID_ADMIN_KEY",
            "message": "ADMIN_PERMANENT_KEY មិនត្រឹមត្រូវទេ។",
        }), 403

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("keys"), list):
        return jsonify({
            "status": "error",
            "message": "ទម្រង់ទិន្នន័យ keys មិនត្រឹមត្រូវទេ។",
        }), 400

    saved = save_keys_vault(payload.get("keys"))
    return jsonify({
        "status": "success",
        "message": "Sync ទៅ Server រួចរាល់",
        "count": len(saved),
        "keys": saved,
    })


@app.route("/api/keys/verify", methods=["POST", "GET"])
def api_keys_verify():
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        if not isinstance(data, dict):
            data = {}
        key_val = data.get("key") or request.form.get("key") or ""
        dev_id = data.get("device_id") or data.get("deviceId") or request.form.get("device_id") or ""
        target_nm = data.get("target_name") or data.get("targetName") or request.form.get("target_name") or ""
        should_bind = data.get("bind", True)
        if isinstance(should_bind, str):
            should_bind = should_bind.lower() not in ("0", "false", "no")
    else:
        key_val = request.args.get("key") or ""
        dev_id = request.args.get("device_id") or request.args.get("deviceId") or ""
        target_nm = request.args.get("target_name") or request.args.get("targetName") or ""
        bind_arg = (request.args.get("bind") or "true").lower()
        should_bind = bind_arg not in ("0", "false", "no")

    ok, code, msg, info = verify_key_remote_or_local(
        key_value=str(key_val),
        device_id=str(dev_id),
        target_name=str(target_nm),
        bind_device=bool(should_bind),
    )
    if not ok:
        status_code = 423 if code == "PAUSED_KEY" else 403
        return jsonify({
            "status": "error",
            "valid": False,
            "code": code,
            "message": msg,
            "telegram_url": ADMIN_TELEGRAM_URL,
            "key_info": info,
        }), status_code

    return jsonify({
        "status": "success",
        "valid": True,
        "code": code,
        "message": msg,
        "key_info": info,
    })


@app.route("/preset-ipas")
def preset_ipas():
    try:
        files = list_preload_ipas()
        return jsonify({"status": "success", "ipas": files})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/clear-temp", methods=["POST"])
def clear_temp_endpoint():
    """Clear temporary uploads/work folders when switching to Upload tab without deleting shared links."""
    clear_active_temp_workspace(active_job_id="", force_all_non_active=True)
    return jsonify({"status": "success", "message": "Temporary workspace cleared"})


@app.route("/clear-all", methods=["POST"])
def clear_all_endpoint():
    """Delete all signed output files, permanent metadata, uploads, and temp folders."""
    with jobs_lock:
        for jid, jdata in list(jobs.items()):
            proc = jdata.get("proc")
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        jobs.clear()

    clear_active_temp_workspace(active_job_id="", force_all_non_active=True)

    for folder in (OUTPUT_DIR, UPLOAD_DIR, TEMP_WORK_DIR):
        if not os.path.isdir(folder):
            continue
        for entry in os.listdir(folder):
            full_path = os.path.join(folder, entry)
            if not is_safe_path(folder, full_path):
                continue
            try:
                if os.path.isdir(full_path) and not os.path.islink(full_path):
                    shutil.rmtree(full_path, ignore_errors=True)
                else:
                    os.remove(full_path)
            except Exception:
                pass

    return jsonify({"status": "success", "message": "បានលុបហ្វាល និងលីងទាំងអស់ដាច់ស្អាតហើយ។"})


@app.route("/sign", methods=["POST"])
def sign_endpoint():
    job_id = uuid.uuid4().hex[:12]
    retention_mode = (request.form.get("retention_mode") or "1h").strip()
    user_key = (request.form.get("admin_key") or "").strip()

    if retention_mode not in ("1h", "permanent"):
        retention_mode = "1h"

    if retention_mode == "permanent":
        if not user_key:
            return jsonify({
                "status": "error",
                "code": "MISSING_ADMIN_KEY",
                "message": "មិនទាន់បានបញ្ចូល Key សម្រាប់រក្សាទុករហូតទេ។ សូម Chat ទៅ Admin ដើម្បីយក Key។",
                "telegram_url": ADMIN_TELEGRAM_URL,
            }), 401

        ok_user_key, _, key_err_msg, _ = verify_key_remote_or_local(
            key_value=user_key,
            device_id=(request.form.get("device_id") or "").strip(),
            target_name="",
            bind_device=True,
        )
        if not ok_user_key:
            return jsonify({
                "status": "error",
                "code": "INVALID_ADMIN_KEY",
                "message": key_err_msg or "ដាក់ Key ខុស ឬបរាជ័យ! សូម Chat ទៅ Admin ដើម្បីទទួលបាន Key ត្រឹមត្រូវ។",
                "telegram_url": ADMIN_TELEGRAM_URL,
            }), 403

    preset_ipa = (request.form.get("preset_ipa") or "").strip()
    ipa_file = request.files.get("ipa_file")
    p12_file = request.files.get("p12_file")
    prov_file = request.files.get("mobileprovision_file")
    custom_icon_file = request.files.get("custom_icon_file")
    tweak_file = request.files.get("tweak_file")

    enable_file_sharing = (request.form.get("enable_file_sharing") or "").lower() in (
        "on", "true", "1", "yes"
    )
    remove_device_limit = (request.form.get("remove_device_limit") or "").lower() in (
        "on", "true", "1", "yes"
    )

    if not p12_file or not p12_file.filename:
        return jsonify({"status": "error", "message": "Missing .p12 certificate file"}), 400
    if not prov_file or not prov_file.filename:
        return jsonify({"status": "error", "message": "Missing .mobileprovision file"}), 400

    clear_active_temp_workspace(active_job_id=job_id, force_all_non_active=True)
    purge_stale_temp_and_expired_files(active_job_id=job_id)
    content_len = request.content_length or 0

    with jobs_lock:
        jobs[job_id] = {
            "job_id": job_id,
            "status": "queued",
            "percent": 0,
            "message": "កំពុងត្រៀម Send...",
            "retention_mode": retention_mode,
            "created_at": time.time(),
            "updated_at": time.time(),
            "cancel_requested": False,
            "filename": "",
            "title": (request.form.get("app_name") or "").strip() or "App",
            "app_name": (request.form.get("app_name") or "").strip() or "App",
            "icon_url": "/static/cheklogo.png",
        }

    try:
        delete_ipa_after_extract = True
        if preset_ipa:
            found_ipa = find_preload_ipa_path(preset_ipa)
            if not found_ipa:
                raise FileNotFoundError("Selected preset IPA not found in preloaded folder")
            ipa_path = found_ipa
            delete_ipa_after_extract = False
            update_job(
                job_id,
                status="running",
                percent=45.0,
                message=f"បានជ្រើស ({format_mb(os.path.getsize(ipa_path))})",
            )
        else:
            if not ipa_file or not ipa_file.filename:
                raise ValueError("Missing IPA file")
            safe_ipa = safe_name(ipa_file.filename, "target.ipa")
            ipa_path = os.path.join(UPLOAD_DIR, f"{job_id}_{safe_ipa}")
            stream_save_upload(ipa_file, ipa_path, job_id, content_len)

        p12_path = os.path.join(UPLOAD_DIR, f"{job_id}_{safe_name(p12_file.filename, 'cert.p12')}")
        prov_path = os.path.join(UPLOAD_DIR, f"{job_id}_{safe_name(prov_file.filename, 'profile.mobileprovision')}")
        p12_file.save(p12_path)
        prov_file.save(prov_path)

        custom_icon_path = None
        if custom_icon_file and custom_icon_file.filename:
            custom_icon_path = os.path.join(
                UPLOAD_DIR, f"{job_id}_{safe_name(custom_icon_file.filename, 'icon.png')}"
            )
            custom_icon_file.save(custom_icon_path)

        tweak_path = None
        if tweak_file and tweak_file.filename:
            tweak_path = os.path.join(
                UPLOAD_DIR, f"{job_id}_{safe_name(tweak_file.filename, 'tweak.dylib')}"
            )
            tweak_file.save(tweak_path)

        params = {
            "ipa_path": ipa_path,
            "delete_ipa_after_extract": delete_ipa_after_extract,
            "p12_path": p12_path,
            "prov_path": prov_path,
            "custom_icon_path": custom_icon_path,
            "tweak_path": tweak_path,
            "enable_file_sharing": enable_file_sharing,
            "remove_device_limit": remove_device_limit,
            "p12_password": request.form.get("p12_password") or "",
            "app_name": request.form.get("app_name") or "",
            "bundle_id": request.form.get("bundle_id") or "",
            "app_version": request.form.get("app_version") or "",
        }

        worker = threading.Thread(target=run_sign_worker, args=(job_id, params), daemon=True)
        worker.start()

        return jsonify({"status": "success", "job_id": job_id})

    except Exception as exc:
        cleanup_job_artifacts(get_job(job_id) or {"job_id": job_id})
        with jobs_lock:
            jobs.pop(job_id, None)
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/progress")
def progress_endpoint():
    job_id = safe_name(request.args.get("job_id") or "")
    j = get_job(job_id)
    if not j:
        return jsonify({
            "status": "cancelled",
            "percent": 0,
            "message": "Cancelled or not found",
            "job_id": job_id,
        })
    return jsonify({
        "status": j.get("status", "running"),
        "percent": j.get("percent", 0),
        "message": j.get("message", ""),
        "filename": j.get("filename", ""),
        "job_id": job_id,
        "title": j.get("title", ""),
        "app_name": j.get("app_name", ""),
        "icon_url": j.get("icon_url", "/static/cheklogo.png"),
    })


@app.route("/cancel", methods=["POST"])
def cancel_endpoint():
    data = request.get_json(silent=True) or {}
    job_id = safe_name(data.get("job_id") or request.form.get("job_id") or "")
    if not job_id:
        purge_stale_temp_and_expired_files()
        return jsonify({"status": "success", "message": "Cancelled"})

    with jobs_lock:
        if job_id in jobs:
            jobs[job_id]["cancel_requested"] = True
            jobs[job_id]["status"] = "cancelled"
            jobs[job_id]["percent"] = 0
            jobs[job_id]["message"] = "Cancelled"
            proc = jobs[job_id].get("proc")
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
            snap = dict(jobs[job_id])
        else:
            snap = {"job_id": job_id}

    cleanup_job_artifacts(snap)
    purge_stale_temp_and_expired_files(active_job_id="")
    return jsonify({"status": "success", "message": "Cancelled"})


@app.route("/job-info")
def job_info_endpoint():
    job_id = safe_name(request.args.get("job_id") or "")
    j = get_job(job_id)
    if not j:
        return jsonify({"status": "error", "message": "Job not found or expired"}), 404

    return jsonify({
        "status": "success",
        "job_id": job_id,
        "title": j.get("title") or j.get("app_name") or "App",
        "app_name": j.get("app_name") or j.get("title") or "App",
        "icon_url": j.get("icon_url") or "/static/cheklogo.png",
        "filename": j.get("filename") or "",
        "retention_mode": j.get("retention_mode") or "1h",
    })


@app.route("/manifest.plist")
def manifest_plist():
    job_id = safe_name(request.args.get("job_id") or "")
    j = get_job(job_id)
    if not j or not j.get("filename"):
        abort(404)

    clean_ipa_name = safe_name(j["filename"])
    ipa_full_path = os.path.join(OUTPUT_DIR, clean_ipa_name)
    if not is_safe_path(OUTPUT_DIR, ipa_full_path) or not os.path.isfile(ipa_full_path):
        abort(404)

    base_title = j.get("title") or j.get("app_name") or "App"
    bundle_id, bundle_version, app_title = _extract_ipa_install_meta(
        ipa_full_path, base_title, job_id
    )

    host_url = request.host_url.rstrip("/")
    if host_url.startswith("http://") and "127.0.0.1" not in host_url and "localhost" not in host_url:
        host_url = "https://" + host_url[len("http://"):]

    ipa_url = html.escape(f"{host_url}/output/{clean_ipa_name}", quote=True)
    safe_bundle_id = html.escape(bundle_id, quote=True)
    safe_version = html.escape(bundle_version, quote=True)
    safe_title = html.escape(app_title, quote=True)

    plist_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
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
        <string>{safe_bundle_id}</string>
        <key>bundle-version</key>
        <string>{safe_version}</string>
        <key>kind</key>
        <string>software</string>
        <key>title</key>
        <string>{safe_title}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>"""

    return Response(plist_xml, mimetype="application/xml; charset=utf-8")


@app.route("/output/<path:filename>")
def output_file(filename):
    clean_file = safe_name(filename)
    full_path = os.path.join(OUTPUT_DIR, clean_file)
    if not is_safe_path(OUTPUT_DIR, full_path) or not os.path.isfile(full_path):
        abort(404)
    return send_from_directory(OUTPUT_DIR, clean_file, as_attachment=False)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8889))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
