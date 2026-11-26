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
    "KEY_SERVER_VERIFY_URL", "https://key-admin.fly.dev/api/keys/verify"
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
    """Sanitize zip member path for macOS APFS so invalid chars never cause Errno 22."""
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


def pre_extract_ipa(ipa_path: str, dest_extract_dir: str, job_id: str, total_bytes: int):
    """Unzip IPA into dest_extract_dir safely, handling macOS APFS invalid filename chars (Errno 22)."""
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
        for temp_in in (p12_src, prov_src, custom_icon_path):
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

        params = {
            "ipa_path": ipa_path,
            "delete_ipa_after_extract": delete_ipa_after_extract,
            "p12_path": p12_path,
            "prov_path": prov_path,
            "custom_icon_path": custom_icon_path,
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
```[cite: 17]

---

### ២. កូដពេញលេញសម្រាប់ `index.html`

```html
<!doctype html>
<html lang="km" class="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CHEK - IPA Signer Online</title>

    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta name="mobile-web-app-capable" content="yes" />
    <meta name="apple-mobile-web-app-status-bar-style" content="black" />
    <meta name="apple-mobile-web-app-title" content="CHEK SIGNER" />

    <link
      rel="icon"
      type="image/png"
      href="{{ url_for('static', filename='cheklogo.png') }}"
    />
    <link
      rel="apple-touch-icon"
      href="{{ url_for('static', filename='cheklogo.png') }}"
    />

    <script src="https://cdn.tailwindcss.com"></script>
    <link
      rel="stylesheet"
      href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"
    />
    <link
      href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600&family=Inter:wght@300;400;500;600;700;800&family=Kantumruy+Pro:wght@400;500;600;700&display=swap"
      rel="stylesheet"
    />

    <script>
      tailwind.config = {
        darkMode: "class",
        theme: {
          extend: {
            colors: {
              pureblack: "#000000",
              blackcard: "#171717",
              blackpanel: "#0a0a0a",
            },
            fontFamily: {
              sans: ["Kantumruy Pro", "Inter", "sans-serif"],
              mono: ["Fira Code", "monospace"],
            },
          },
        },
      };
    </script>
    <style>
      button,
      label,
      input,
      select,
      a {
        touch-action: manipulation;
        -webkit-tap-highlight-color: transparent;
      }
      input[type="checkbox"] {
        touch-action: manipulation;
        -webkit-tap-highlight-color: transparent;
        cursor: pointer;
      }
      .white-highlight {
        color: #ffffff;
        background: rgba(255, 255, 255, 0.14);
        padding: 0.08em 0.38em;
        border-radius: 0.35rem;
      }
    </style>
  </head>
  <body
    class="bg-pureblack text-neutral-100 font-sans min-h-screen flex flex-col justify-between selection:bg-white/25 selection:text-white"
  >
    <!-- HEADER -->
    <header
      id="main-header"
      class="border-b border-neutral-800/90 bg-pureblack/95 backdrop-blur-md sticky top-0 z-50"
    >
      <div
        class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between"
      >
        <div class="flex items-center space-x-3">
          <div
            class="w-10 h-10 rounded-xl bg-gradient-to-tr from-white to-neutral-300 flex items-center justify-center text-black font-black text-xl shadow-md"
          >
            CS
          </div>
          <div>
            <h1 class="text-xl font-extrabold tracking-wider text-white">
              <span class="white-highlight">CHEK SIGNER</span>
            </h1>
            <p class="text-xs text-neutral-300">
              IPA Signer & Resigning System
            </p>
          </div>
        </div>

        <!-- LANGUAGE SWITCHER -->
        <div
          class="flex items-center space-x-2 bg-blackpanel p-1 rounded-xl border border-neutral-800"
        >
          <button
            type="button"
            onclick="setLanguage('km')"
            id="lang-km"
            class="px-2.5 py-1 rounded-lg text-xs font-bold bg-white text-black transition-all"
          >
            ខ្មែរ
          </button>
          <button
            type="button"
            onclick="setLanguage('en')"
            id="lang-en"
            class="px-2.5 py-1 rounded-lg text-xs font-bold text-neutral-300 hover:text-white transition-all"
          >
            EN
          </button>
        </div>
      </div>
    </header>

    <!-- MAIN CONTENT AREA -->
    <main
      class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 flex flex-col items-center justify-center bg-pureblack"
    >
      <!-- DEDICATED CLEAN INSTALL CARD (SHARE LINK VIEW) -->
      <div
        id="shared-install-view"
        class="hidden w-full max-w-sm mx-auto bg-blackcard border border-neutral-800 rounded-3xl p-8 shadow-2xl text-center space-y-6 my-auto"
      >
        <div
          class="w-28 h-28 mx-auto rounded-3xl p-1 bg-gradient-to-tr from-white via-neutral-200 to-neutral-400 shadow-lg flex items-center justify-center overflow-hidden"
        >
          <img
            src="{{ url_for('static', filename='cheklogo.png') }}"
            data-fallback="{{ url_for('static', filename='cheklogo.png') }}"
            alt="App Logo"
            class="w-full h-full object-cover rounded-2xl bg-pureblack"
            id="shared-app-logo"
          />
        </div>

        <div class="space-y-1">
          <h2
            id="shared-app-title"
            class="text-2xl font-black text-white tracking-wide"
          >
            App Name
          </h2>
          <p class="text-xs text-neutral-300" data-translate="installSub">
            application on your iPhone or iPad.
          </p>
        </div>

        <div class="pt-2 space-y-3">
          <a
            id="shared-install-btn"
            href="#"
            class="w-full bg-white hover:bg-neutral-200 active:scale-95 text-black font-bold py-3.5 px-6 rounded-2xl shadow-lg transition-all flex items-center justify-center gap-2 text-base"
          >
            <i class="fa-solid fa-download"></i>
            <span data-translate="installBtn">Install App</span>
          </a>
        </div>
      </div>

      <!-- NORMAL UPLOAD & SIGN VIEW -->
      <div
        id="normal-app-container"
        class="w-full space-y-8 flex flex-col items-center"
      >
        <div
          id="main-banner"
          class="bg-blackcard border border-neutral-800 rounded-3xl p-6 sm:p-10 shadow-2xl relative overflow-hidden flex flex-col items-center text-center space-y-6 w-full max-w-3xl"
        >
          <div class="relative z-10 flex flex-col items-center space-y-3">
            <div
              class="w-24 h-24 sm:w-28 sm:h-28 rounded-2xl p-1 bg-gradient-to-tr from-white to-neutral-300 shadow-lg"
            >
              <img
                src="{{ url_for('static', filename='cheklogo.png') }}"
                alt="CHEK STORE Logo"
                class="w-full h-full object-cover rounded-xl bg-pureblack"
              />
            </div>
            <h2
              class="text-xl sm:text-2xl font-black tracking-wider text-white"
            >
              <span class="white-highlight">IPA SIGNER ONLINE</span>
            </h2>
          </div>
        </div>

        <!-- FORM & PROGRESS SECTION -->
        <div
          id="form-section"
          class="grid grid-cols-1 lg:grid-cols-12 gap-8 w-full max-w-5xl"
        >
          <div id="sign-form-container" class="lg:col-span-7 space-y-6">
            <form
              id="sign-form"
              class="bg-blackcard border border-neutral-800 rounded-2xl p-6 shadow-xl space-y-5"
            >
              <h2 class="text-lg font-bold text-white flex items-center gap-2">
                <i class="fa-solid fa-file-signature text-white"></i>
                <span data-translate="formTitle" class="white-highlight"
                  >ជ្រើសរើសហ្វាល IPA និង Certificate</span
                >
              </h2>

              <!-- SELECTOR TAB -->
              <div
                class="grid grid-cols-2 gap-2 bg-pureblack p-1.5 rounded-xl border border-neutral-800"
              >
                <button
                  type="button"
                  id="tab-upload"
                  onclick="switchSource('upload')"
                  class="py-2 rounded-lg text-xs font-bold bg-white text-black transition-all"
                >
                  <i class="fa-solid fa-cloud-arrow-up mr-1"></i>
                  <span data-translate="tabUpload">Upload IPA ថ្មី</span>
                </button>
                <button
                  type="button"
                  id="tab-preset"
                  onclick="switchSource('preset')"
                  class="py-2 rounded-lg text-xs font-bold text-neutral-300 hover:text-white transition-all"
                >
                  <i class="fa-solid fa-box-archive mr-1"></i>
                  <span data-translate="tabPreset"
                    >App ស្រាប់ក្នុងប្រព័ន្ធ</span
                  >
                </button>
              </div>

              <!-- OPTION A: UPLOAD -->
              <div id="source-upload-container">
                <label
                  class="block text-xs font-semibold text-white mb-2"
                  data-translate="labelIpa"
                  >១. ហ្វាល IPA (TARGET IPA FILE)</label
                >
                <label
                  for="ipa-file-input"
                  id="drop-zone"
                  class="border-2 border-dashed border-neutral-700 hover:border-white bg-pureblack rounded-xl p-6 text-center transition-all cursor-pointer group relative block"
                >
                  <input
                    type="file"
                    id="ipa-file-input"
                    name="ipa_file"
                    accept=".ipa"
                    class="hidden"
                  />
                  <div class="space-y-3" id="drop-zone-idle">
                    <div
                      class="w-14 h-14 mx-auto rounded-full bg-neutral-900 group-hover:bg-white/15 flex items-center justify-center text-white transition-colors"
                    >
                      <i class="fa-brands fa-apple text-3xl"></i>
                    </div>
                    <div>
                      <p
                        class="text-sm font-semibold text-white"
                        data-translate="dropText"
                      >
                        ចុចទីនេះដើម្បីជ្រើសរើស ឬទាញទម្លាក់ហ្វាល IPA
                      </p>
                      <p
                        class="text-xs text-neutral-400 mt-1"
                        data-translate="dropSub"
                      >
                        គាំទ្រហ្វាល IPA គ្រប់ទំហំ
                      </p>
                    </div>
                  </div>

                  <div
                    id="file-info"
                    class="hidden flex items-center justify-between bg-blackpanel p-4 rounded-lg border border-neutral-800"
                  >
                    <div
                      class="flex items-center space-x-3 overflow-hidden text-left"
                    >
                      <div
                        class="w-10 h-10 rounded bg-white/10 text-white flex items-center justify-center shrink-0"
                      >
                        <i class="fa-solid fa-mobile-screen text-lg"></i>
                      </div>
                      <div class="truncate">
                        <p
                          id="file-name"
                          class="text-sm font-semibold text-white truncate"
                        >
                          app.ipa
                        </p>
                        <p id="file-size" class="text-xs text-neutral-400">
                          0 MB
                        </p>
                      </div>
                    </div>
                    <button
                      type="button"
                      id="remove-file-btn"
                      class="text-neutral-400 hover:text-white p-2 text-sm transition-colors"
                    >
                      <i class="fa-solid fa-xmark"></i>
                    </button>
                  </div>
                </label>
              </div>

              <!-- OPTION B: PRESET -->
              <div id="source-preset-container" class="hidden space-y-3">
                <label
                  class="block text-xs font-semibold text-white mb-2"
                  data-translate="labelPreset"
                  >១. ជ្រើសរើស App ស្រាប់ដែលមានក្នុងប្រព័ន្ធ</label
                >
                <select
                  id="preset-ipa-select"
                  name="preset_ipa"
                  class="w-full bg-pureblack border border-neutral-800 focus:border-white rounded-xl px-4 py-3 text-sm text-white outline-none transition-colors"
                >
                  <option value="">-- Loading available apps... --</option>
                </select>
              </div>

              <!-- APP NAME, BUNDLE ID & VERSION -->
              <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div>
                  <label
                    class="block text-xs font-semibold text-white mb-2"
                    data-translate="labelAppName"
                    >APP NAME (ប្តូរឈ្មោះ App)</label
                  >
                  <input
                    type="text"
                    id="app-name-input"
                    name="app_name"
                    placeholder="ឈ្មោះ App ថ្មី..."
                    class="w-full bg-pureblack border border-neutral-800 focus:border-white rounded-lg px-3 py-2.5 text-sm text-white placeholder-neutral-400 outline-none transition-colors"
                  />
                </div>

                <div>
                  <label
                    class="block text-xs font-semibold text-white mb-2"
                    data-translate="labelBundleId"
                    >BUNDLE ID (ប្តូរ ID App)</label
                  >
                  <input
                    type="text"
                    id="bundle-id-input"
                    name="bundle_id"
                    placeholder="com.chek.app"
                    class="w-full bg-pureblack border border-neutral-800 focus:border-white rounded-lg px-3 py-2.5 text-sm text-white placeholder-neutral-400 outline-none transition-colors font-mono"
                  />
                </div>

                <div>
                  <label
                    class="block text-xs font-semibold text-white mb-2"
                    data-translate="labelAppVersion"
                    >APP VERSION (ប្តូរ Version)</label
                  >
                  <input
                    type="text"
                    id="app-version-input"
                    name="app_version"
                    placeholder="1.0.0"
                    class="w-full bg-pureblack border border-neutral-800 focus:border-white rounded-lg px-3 py-2.5 text-sm text-white placeholder-neutral-400 outline-none transition-colors font-mono"
                  />
                </div>
              </div>

              <!-- CERTIFICATE (.P12) & PROVISIONING -->
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label
                    class="block text-xs font-semibold text-white mb-2"
                    data-translate="labelP12"
                    >២. CERTIFICATE (.P12)</label
                  >
                  <input
                    type="file"
                    id="p12-file-input"
                    name="p12_file"
                    accept=".p12"
                    class="hidden"
                  />
                  <button
                    type="button"
                    onclick="document.getElementById('p12-file-input').click()"
                    class="w-full bg-pureblack border border-neutral-800 hover:border-white text-left px-3.5 py-2.5 rounded-lg text-xs text-neutral-200 flex items-center justify-between"
                  >
                    <span
                      id="p12-name"
                      class="truncate text-white font-medium"
                      data-translate="selectP12"
                      >ជ្រើសរើសហ្វាល .p12</span
                    >
                    <i class="fa-solid fa-file-contract text-white"></i>
                  </button>
                </div>

                <div>
                  <label
                    class="block text-xs font-semibold text-white mb-2"
                    data-translate="labelProv"
                    >៣. PROVISIONING PROFILE</label
                  >
                  <input
                    type="file"
                    id="prov-file-input"
                    name="mobileprovision_file"
                    accept=".mobileprovision"
                    class="hidden"
                  />
                  <button
                    type="button"
                    onclick="document.getElementById('prov-file-input').click()"
                    class="w-full bg-pureblack border border-neutral-800 hover:border-white text-left px-3.5 py-2.5 rounded-lg text-xs text-neutral-200 flex items-center justify-between"
                  >
                    <span
                      id="prov-name"
                      class="truncate text-white font-medium"
                      data-translate="selectProv"
                      >ជ្រើសរើស .mobileprovision</span
                    >
                    <i class="fa-solid fa-id-card text-white"></i>
                  </button>
                </div>
              </div>

              <!-- PASSWORD -->
              <div>
                <label
                  for="p12-password"
                  class="block text-xs font-semibold text-white mb-2"
                  data-translate="labelPass"
                  >លេខសម្ងាត់ P12 PASSWORD</label
                >
                <input
                  type="password"
                  id="p12-password"
                  name="p12_password"
                  placeholder="បញ្ចូល Password របស់ .p12 (បើមាន)"
                  class="w-full bg-pureblack border border-neutral-800 focus:border-white rounded-lg px-3.5 py-2.5 text-sm text-white placeholder-neutral-400 outline-none transition-colors font-mono"
                />
              </div>

              <!-- OPTIONAL CUSTOMIZATION (ICON, DYLIB/DEB, PLIST FLAGS) -->
              <div
                class="bg-pureblack border border-neutral-800 rounded-xl p-4 space-y-4"
              >
                <p
                  class="text-xs font-bold text-white flex items-center gap-1.5"
                >
                  <i class="fa-solid fa-sliders text-white"></i>
                  <span data-translate="extraTitle" class="white-highlight"
                    >ជម្រើសបន្ថែម (ប្តូរ Icon / Inject Dylib & Deb / សិទ្ធិ
                    Files)</span
                  >
                </p>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label
                      class="block text-xs font-semibold text-white mb-1.5"
                      data-translate="labelIcon"
                      >ប្តូរ ICON APP (.PNG / .JPG)</label
                    >
                    <input
                      type="file"
                      id="icon-file-input"
                      name="custom_icon_file"
                      accept="image/png,image/jpeg"
                      class="hidden"
                    />
                    <button
                      type="button"
                      onclick="
                        document.getElementById('icon-file-input').click()
                      "
                      class="w-full bg-blackcard border border-neutral-800 hover:border-white text-left px-3 py-2 rounded-lg text-xs text-neutral-200 flex items-center justify-between"
                    >
                      <span
                        id="icon-name"
                        class="truncate text-white font-medium"
                        data-translate="selectIcon"
                        >ជ្រើសរើសរូបភាព Icon (បើចង់ប្តូរ)</span
                      >
                      <i class="fa-solid fa-image text-white"></i>
                    </button>
                  </div>

                  <div>
                    <label
                      class="block text-xs font-semibold text-white mb-1.5"
                      data-translate="labelTweak"
                      >INJECT DYLIB / DEB (បញ្ចូល Tweak)</label
                    >
                    <input
                      type="file"
                      id="tweak-file-input"
                      name="tweak_file"
                      accept=".dylib,.deb"
                      class="hidden"
                    />
                    <button
                      type="button"
                      onclick="
                        document.getElementById('tweak-file-input').click()
                      "
                      class="w-full bg-blackcard border border-neutral-800 hover:border-white text-left px-3 py-2 rounded-lg text-xs text-neutral-200 flex items-center justify-between"
                    >
                      <span
                        id="tweak-name"
                        class="truncate text-white font-medium"
                        data-translate="selectTweak"
                        >ជ្រើសរើស .dylib ឬ .deb (បើមាន)</span
                      >
                      <i class="fa-solid fa-puzzle-piece text-white"></i>
                    </button>
                  </div>
                </div>

                <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
                  <label
                    class="flex items-center gap-2 text-xs font-medium text-neutral-200 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      id="enable-file-sharing-checkbox"
                      name="enable_file_sharing"
                      class="w-4 h-4 accent-white rounded"
                    />
                    <span data-translate="optFileSharing"
                      >បើក File Sharing (មើលក្នុង Files App)</span
                    >
                  </label>

                  <label
                    class="flex items-center gap-2 text-xs font-medium text-neutral-200 cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      id="remove-device-limit-checkbox"
                      name="remove_device_limit"
                      class="w-4 h-4 accent-white rounded"
                    />
                    <span data-translate="optDeviceLimit"
                      >លុបកម្រិតឧបករណ៍ (ដំឡើងបានទាំង iPad)</span
                    >
                  </label>
                </div>

                <!-- ADMIN RETENTION SELECTOR (1 HOUR vs UNLIMITED) -->
                <div class="pt-3 border-t border-neutral-800 space-y-2.5">
                  <div
                    class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2"
                  >
                    <label
                      for="retention-mode-select"
                      class="text-xs font-semibold text-white flex items-center gap-1.5"
                    >
                      <i class="fa-solid fa-shield-halved text-white"></i>
                      <span data-translate="labelRetention"
                        >រយៈពេល Link & ហ្វាល់</span
                      >
                    </label>
                    <select
                      id="retention-mode-select"
                      name="retention_mode"
                      onchange="toggleAdminKeyBox()"
                      class="bg-blackcard border border-neutral-700 focus:border-white rounded-lg px-3 py-2 text-xs text-white outline-none"
                    >
                      <option value="1h" selected data-translate="retOneHour">
                        ១ ម៉ោង (លុបស្វ័យប្រវត្តិ)
                      </option>
                      <option value="permanent" data-translate="retPermanent">
                        រក្សាទុករហូត / ឥតដែនកំណត់ (Admin)
                      </option>
                    </select>
                  </div>

                  <div id="admin-key-container" class="hidden space-y-2">
                    <input
                      type="password"
                      id="admin-key-input"
                      name="admin_key"
                      oninput="hideAdminKeyBoxAlert()"
                      placeholder="បញ្ចូល Admin Key ដើម្បីបង្កើត Link ប្រើរហូត..."
                      class="w-full bg-blackcard border border-neutral-700 focus:border-white rounded-lg px-3 py-2 text-xs text-white placeholder-neutral-400 outline-none font-mono"
                    />

                    <!-- KEY MISSING / INVALID BOX + SMALL CHAT ADMIN BUTTON BELOW -->
                    <div
                      id="admin-key-alert-box"
                      class="hidden bg-blackcard border border-neutral-700 rounded-lg p-2.5 space-y-2"
                    >
                      <p
                        id="admin-key-alert-msg"
                        class="text-xs font-medium text-neutral-200"
                      >
                        មិនទាន់មាន Key ទេ
                      </p>
                      <div class="flex justify-end">
                        <a
                          id="admin-key-telegram-btn"
                          href="https://t.me/chinchek55"
                          target="_blank"
                          rel="noopener noreferrer"
                          class="inline-flex items-center gap-1.5 bg-white hover:bg-neutral-200 text-black font-bold px-2.5 py-1 rounded-md text-[11px] transition-all"
                        >
                          <i class="fa-brands fa-telegram text-xs"></i>
                          <span data-translate="chatAdminBtn">Chat Admin</span>
                        </a>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <!-- SUBMIT -->
              <button
                type="submit"
                id="start-sign-btn"
                class="w-full bg-gradient-to-r from-white to-neutral-200 hover:from-neutral-100 hover:to-neutral-300 text-black font-bold py-3.5 px-6 rounded-xl shadow-lg transition-all flex items-center justify-center gap-2 text-base"
              >
                <i class="fa-solid fa-bolt"></i>
                <span data-translate="signBtn">ចាប់ផ្តើម Sign IPA ឥឡូវនេះ</span>
              </button>
            </form>
          </div>

          <!-- TELEMETRY -->
          <div id="telemetry-panel" class="lg:col-span-5 space-y-6 w-full">
            <div
              class="bg-blackcard border border-neutral-800 rounded-2xl p-6 shadow-xl space-y-6"
            >
              <h2 class="text-lg font-bold text-white flex items-center gap-2">
                <i class="fa-solid fa-chart-line text-white"></i>
                <span data-translate="statusTitle" class="white-highlight"
                  >ស្ថានភាពនៃការ Sign</span
                >
              </h2>

              <div
                class="bg-pureblack border border-neutral-800 rounded-xl p-5 space-y-4"
              >
                <div class="flex justify-between items-center text-sm">
                  <span
                    id="status-label"
                    class="text-neutral-200 font-medium"
                    data-translate="statusWait"
                    >ស្ថានភាព៖ រង់ចាំ</span
                  >
                  <span
                    id="progress-percent"
                    class="font-mono text-white font-bold"
                    >0.00%</span
                  >
                </div>

                <div id="progress-container">
                  <div
                    class="w-full bg-neutral-900 h-3 rounded-full overflow-hidden p-0.5 border border-neutral-800"
                  >
                    <div
                      id="progress-bar-fill"
                      class="bg-gradient-to-r from-white to-neutral-300 h-full rounded-full w-0 transition-all duration-300"
                    ></div>
                  </div>
                </div>

                <!-- CANCEL SIGN BUTTON (SHOWN WHILE SIGNING) -->
                <button
                  type="button"
                  id="cancel-sign-btn"
                  onclick="cancelCurrentSigning()"
                  class="hidden w-full bg-blackpanel hover:bg-neutral-800 active:scale-[0.99] text-white font-bold py-2.5 px-4 rounded-xl border border-neutral-700 transition-all flex items-center justify-center gap-2 text-xs"
                >
                  <i class="fa-solid fa-ban text-white"></i>
                  <span data-translate="cancelSignBtn"
                    >បោះបង់ការ Sign (Cancel)</span
                  >
                </button>

                <!-- CLEAR ALL FILES & LINKS BUTTON -->
                <button
                  type="button"
                  id="clear-all-btn"
                  onclick="clearAllSignedData()"
                  class="w-full bg-blackpanel hover:bg-neutral-800 text-white font-bold py-2 px-4 rounded-xl border border-neutral-700 transition-all text-xs"
                >
                  លុបហ្វាល & លីងទាំងអស់
                </button>

                <!-- SUCCESS BOX -->
                <div
                  id="success-message-box"
                  class="hidden py-4 px-3 text-center bg-blackpanel border border-neutral-700 rounded-xl space-y-3"
                >
                  <span
                    class="text-white font-black text-base sm:text-lg tracking-wider flex items-center justify-center gap-2"
                  >
                    <i class="fa-solid fa-circle-check text-xl text-white"></i>
                    <span data-translate="successText" class="white-highlight"
                      >Sign ជោគជ័យ!</span
                    >
                  </span>

                  <div
                    class="flex flex-wrap items-center justify-center gap-2 pt-1"
                  >
                    <a
                      id="install-app-btn"
                      href="#"
                      class="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-white hover:bg-neutral-200 text-black font-bold text-xs transition-colors shadow-md"
                    >
                      <i class="fa-solid fa-download"></i>
                      <span data-translate="installBtn">Install App</span>
                    </a>

                    <a
                      id="download-signed-ipa"
                      href="#"
                      download
                      class="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-neutral-200 hover:bg-white text-black font-bold text-xs transition-colors shadow-md"
                    >
                      <i class="fa-solid fa-file-arrow-down"></i>
                      <span data-translate="downloadBtn">Download</span>
                    </a>

                    <button
                      type="button"
                      id="copy-link-btn"
                      onclick="copySignedLink()"
                      class="inline-flex items-center gap-1.5 px-3 py-2 rounded-xl bg-blackcard hover:bg-neutral-800 text-white font-bold text-xs transition-colors border border-neutral-700"
                    >
                      <i class="fa-solid fa-copy text-white"></i>
                      <span id="copy-btn-text" data-translate="copyBtn"
                        >Copy Link</span
                      >
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </main>

    <!-- FOOTER -->
    <footer
      id="main-footer-section"
      class="border-t border-neutral-800 bg-pureblack py-6 text-center text-xs text-neutral-300 space-y-3"
    >
      <div class="flex items-center justify-center gap-3 flex-wrap px-4">
        <a
          href="https://t.me/channelchinchek12"
          target="_blank"
          class="inline-flex items-center gap-2 bg-blackpanel hover:bg-neutral-800 text-white font-semibold px-4 py-2 rounded-xl border border-neutral-700 transition-all text-xs shadow-sm"
        >
          <i class="fa-brands fa-telegram text-base text-white"></i>
          <span>Join Telegram Channel</span>
        </a>

        <a
          href="https://t.me/chinchek55"
          target="_blank"
          class="inline-flex items-center gap-2 bg-blackpanel hover:bg-neutral-800 text-white font-semibold px-4 py-2 rounded-xl border border-neutral-700 transition-all text-xs shadow-sm"
        >
          <i class="fa-solid fa-headset text-base text-white"></i>
          <span>Support Admin</span>
        </a>
      </div>
      <p>
        © 2026 <span class="white-highlight">CHEK STORE</span> - IPA Signer
        Tool. All rights reserved.
      </p>
    </footer>

    <!-- SCRIPT & TRANSLATIONS -->
    <script>
      const ADMIN_TELEGRAM_URL = "https://t.me/chinchek55";

      const translations = {
        km: {
          installSub: "application on your iPhone or iPad.",
          installBtn: "Install App",
          formTitle: "ជ្រើសរើសហ្វាល IPA និង Certificate",
          tabUpload: "Upload IPA ថ្មី",
          tabPreset: "App ស្រាប់ក្នុងប្រព័ន្ធ",
          labelIpa: "១. ហ្វាល IPA (TARGET IPA FILE)",
          dropText: "ចុចទីនេះដើម្បីជ្រើសរើស ឬទាញទម្លាក់ហ្វាល IPA",
          dropSub: "គាំទ្រហ្វាល IPA គ្រប់ទំហំ",
          labelPreset: "១. ជ្រើសរើស App ស្រាប់ដែលមានក្នុងប្រព័ន្ធ",
          labelAppName: "APP NAME (ប្តូរឈ្មោះ App)",
          labelBundleId: "BUNDLE ID (ប្តូរ ID App)",
          labelAppVersion: "APP VERSION (ប្តូរ Version)",
          labelP12: "២. CERTIFICATE (.P12)",
          selectP12: "ជ្រើសរើសហ្វាល .p12",
          labelProv: "៣. PROVISIONING PROFILE",
          selectProv: "ជ្រើសរើស .mobileprovision",
          labelPass: "លេខសម្ងាត់ P12 PASSWORD",
          extraTitle:
            "ជម្រើសបន្ថែម (ប្តូរ Icon / Inject Dylib & Deb / សិទ្ធិ Files)",
          labelIcon: "ប្តូរ ICON APP (.PNG / .JPG)",
          selectIcon: "ជ្រើសរើសរូបភាព Icon (បើចង់ប្តូរ)",
          labelTweak: "INJECT DYLIB / DEB (បញ្ចូល Tweak)",
          selectTweak: "ជ្រើសរើស .dylib ឬ .deb (បើមាន)",
          optFileSharing: "បើក File Sharing (មើលក្នុង Files App)",
          optDeviceLimit: "លុបកម្រិតឧបករណ៍ (ដំឡើងបានទាំង iPad)",
          labelRetention: "រយៈពេល Link & ហ្វាល់",
          retOneHour: "១ ម៉ោង (លុបស្វ័យប្រវត្តិ)",
          retPermanent: "រក្សាទុករហូត / ឥតដែនកំណត់ (Admin)",
          chatAdminBtn: "Chat Admin",
          signBtn: "ចាប់ផ្តើម Sign IPA ឥឡូវនេះ",
          cancelSignBtn: "បោះបង់ការ Sign (Cancel)",
          statusTitle: "ស្ថានភាពនៃការ Sign",
          statusWait: "ស្ថានភាព៖ រង់ចាំ",
          successText: "Sign ជោគជ័យ!",
          downloadBtn: "Download",
          copyBtn: "Copy Link",
        },
        en: {
          installSub: "application on your iPhone or iPad.",
          installBtn: "Install App",
          formTitle: "Select IPA File & Certificate",
          tabUpload: "Upload New IPA",
          tabPreset: "Preloaded Apps",
          labelIpa: "1. TARGET IPA FILE",
          dropText: "Click here or drag & drop IPA file",
          dropSub: "Support all IPA file sizes",
          labelPreset: "1. Select Preloaded App",
          labelAppName: "APP NAME (Custom Name)",
          labelBundleId: "BUNDLE ID (Custom ID)",
          labelAppVersion: "APP VERSION (Custom Version)",
          labelP12: "2. CERTIFICATE (.P12)",
          selectP12: "Select .p12 file",
          labelProv: "3. PROVISIONING PROFILE",
          selectProv: "Select .mobileprovision",
          labelPass: "P12 PASSWORD",
          extraTitle:
            "Extra Options (Custom Icon / Inject Dylib & Deb / Plist)",
          labelIcon: "CUSTOM APP ICON (.PNG / .JPG)",
          selectIcon: "Select custom icon (optional)",
          labelTweak: "INJECT DYLIB / DEB (Tweak)",
          selectTweak: "Select .dylib or .deb (optional)",
          optFileSharing: "Enable File Sharing (Files App)",
          optDeviceLimit: "Remove Device Restriction (iPad Support)",
          labelRetention: "Link & File Retention",
          retOneHour: "1 Hour (Auto Delete)",
          retPermanent: "Unlimited / Permanent (Admin)",
          chatAdminBtn: "Chat Admin",
          signBtn: "Start Signing IPA Now",
          cancelSignBtn: "Cancel Signing",
          statusTitle: "Signing Status",
          statusWait: "Status: Waiting",
          successText: "Successfully Signed!",
          downloadBtn: "Download",
          copyBtn: "Copy Link",
        },
      };

      function hideAdminKeyBoxAlert() {
        const box = document.getElementById("admin-key-alert-box");
        if (box) box.classList.add("hidden");
      }

      function showAdminKeyBoxAlert(msgText, tgUrl) {
        const box = document.getElementById("admin-key-alert-box");
        const msg = document.getElementById("admin-key-alert-msg");
        const link = document.getElementById("admin-key-telegram-btn");
        if (msg) msg.textContent = msgText;
        if (link) link.href = tgUrl || ADMIN_TELEGRAM_URL;
        if (box) box.classList.remove("hidden");
      }

      function toggleAdminKeyBox() {
        const modeEl = document.getElementById("retention-mode-select");
        const keyBox = document.getElementById("admin-key-container");
        if (!modeEl || !keyBox) return;
        if (modeEl.value === "permanent") {
          keyBox.classList.remove("hidden");
        } else {
          keyBox.classList.add("hidden");
          hideAdminKeyBoxAlert();
        }
      }

      function setLanguage(lang) {
        document.getElementById("lang-km").className =
          lang === "km"
            ? "px-2.5 py-1 rounded-lg text-xs font-bold bg-white text-black transition-all"
            : "px-2.5 py-1 rounded-lg text-xs font-bold text-neutral-300 hover:text-white transition-all";
        document.getElementById("lang-en").className =
          lang === "en"
            ? "px-2.5 py-1 rounded-lg text-xs font-bold bg-white text-black transition-all"
            : "px-2.5 py-1 rounded-lg text-xs font-bold text-neutral-300 hover:text-white transition-all";

        document.querySelectorAll("[data-translate]").forEach((el) => {
          const key = el.getAttribute("data-translate");
          if (translations[lang][key]) {
            el.textContent = translations[lang][key];
          }
        });
      }

      let currentSource = "upload";

      function switchSource(type) {
        currentSource = type;
        const btnUpload = document.getElementById("tab-upload");
        const btnPreset = document.getElementById("tab-preset");
        const boxUpload = document.getElementById("source-upload-container");
        const boxPreset = document.getElementById("source-preset-container");

        if (type === "upload") {
          btnUpload.className =
            "py-2 rounded-lg text-xs font-bold bg-white text-black transition-all";
          btnPreset.className =
            "py-2 rounded-lg text-xs font-bold text-neutral-300 hover:text-white transition-all";
          boxUpload.classList.remove("hidden");
          boxPreset.classList.add("hidden");
        } else {
          btnPreset.className =
            "py-2 rounded-lg text-xs font-bold bg-white text-black transition-all";
          btnUpload.className =
            "py-2 rounded-lg text-xs font-bold text-neutral-300 hover:text-white transition-all";
          boxPreset.classList.remove("hidden");
          boxUpload.classList.add("hidden");
          loadPresetIpas();
        }
      }

      function loadPresetIpas() {
        fetch("/preset-ipas")
          .then((res) => res.json())
          .then((data) => {
            const selectEl = document.getElementById("preset-ipa-select");
            selectEl.innerHTML = "";
            if (data.status === "success" && data.ipas.length > 0) {
              data.ipas.forEach((filename) => {
                const opt = document.createElement("option");
                opt.value = filename;
                opt.textContent = filename;
                selectEl.appendChild(opt);
              });
            } else {
              const opt = document.createElement("option");
              opt.value = "";
              opt.textContent = "-- No available apps in preloaded folder --";
              selectEl.appendChild(opt);
            }
          })
          .catch((err) => console.error("Error loading presets:", err));
      }

      let lastGeneratedJobId = "";
      let lastGeneratedFilename = "";
      let currentSigningJobId = "";
      let activePollTimer = null;
      let activeSignAbort = null;
      let activePollAbort = null;
      let activeRunId = 0;

      function cleanZsignError(rawMsg) {
        const stripped = String(rawMsg || "")
          .replace(/\x1b\[[0-9;]*m/g, "")
          .replace(/\[[0-9;]*m/g, "")
          .trim();
        const lines = stripped
          .split(/\r?\n/)
          .map((l) => l.trim())
          .filter(Boolean);
        if (lines.length <= 2) return stripped;
        return lines.slice(-3).join("\n");
      }

      function stopAllSignNetwork() {
        if (activePollTimer) {
          clearInterval(activePollTimer);
          activePollTimer = null;
        }
        if (activeSignAbort) {
          try {
            activeSignAbort.abort();
          } catch (e) {}
          activeSignAbort = null;
        }
        if (activePollAbort) {
          try {
            activePollAbort.abort();
          } catch (e) {}
          activePollAbort = null;
        }
      }

      function setSignButtonBusy(isBusy) {
        const btn = document.getElementById("start-sign-btn");
        const cancelBtn = document.getElementById("cancel-sign-btn");
        if (btn) {
          btn.disabled = Boolean(isBusy);
          if (isBusy) {
            btn.classList.add("opacity-60", "cursor-not-allowed");
          } else {
            btn.classList.remove("opacity-60", "cursor-not-allowed");
          }
        }
        if (cancelBtn) {
          if (isBusy) {
            cancelBtn.classList.remove("hidden");
          } else {
            cancelBtn.classList.add("hidden");
          }
        }
      }

      function cancelCurrentSigning() {
        activeRunId++;
        stopAllSignNetwork();

        const jobId = currentSigningJobId;
        currentSigningJobId = "";

        const bar = document.getElementById("progress-bar-fill");
        const pct = document.getElementById("progress-percent");
        const lbl = document.getElementById("status-label");
        const box = document.getElementById("success-message-box");

        if (bar) {
          bar.style.transition = "none";
          bar.style.width = "0%";
          void bar.offsetWidth;
          bar.style.transition = "";
        }
        if (pct) pct.textContent = "0.00%";
        if (box) box.classList.add("hidden");
        if (lbl) lbl.textContent = "ស្ថានភាព៖ បានបោះបង់ (Cancelled)";

        setSignButtonBusy(false);

        if (jobId) {
          fetch("/cancel", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ job_id: jobId }),
            keepalive: true,
          }).catch(() => {});
        }
      }

      function getCurrentOrigin(forceHttpsForManifest = false) {
        let origin = window.location.origin;
        if (forceHttpsForManifest && origin.startsWith("http://")) {
          origin = origin.replace("http://", "https://");
        }
        return origin;
      }

      function copyTextFallback(text) {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.top = "-1000px";
        ta.style.left = "-1000px";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        let ok = false;
        try {
          ok = document.execCommand("copy");
        } catch (e) {
          ok = false;
        }
        document.body.removeChild(ta);
        return ok;
      }

      function markCopiedUi() {
        const copyText = document.getElementById("copy-btn-text");
        if (copyText) {
          copyText.textContent = "Copied Link!";
          setTimeout(() => {
            copyText.textContent = "Copy Link";
          }, 2000);
        }
      }

      function copySignedLink() {
        if (!lastGeneratedJobId && !lastGeneratedFilename) {
          alert("សូម Sign IPA ជាមុនសិន!");
          return;
        }
        const origin = getCurrentOrigin(false);
        const shareUrl = lastGeneratedJobId
          ? origin + "/?job_id=" + encodeURIComponent(lastGeneratedJobId)
          : origin + "/output/" + encodeURIComponent(lastGeneratedFilename);

        if (navigator.clipboard && window.isSecureContext) {
          navigator.clipboard
            .writeText(shareUrl)
            .then(markCopiedUi)
            .catch(() => {
              if (copyTextFallback(shareUrl)) {
                markCopiedUi();
              } else {
                prompt("ចម្លង Link ដោយដៃ៖", shareUrl);
              }
            });
        } else {
          if (copyTextFallback(shareUrl)) {
            markCopiedUi();
          } else {
            prompt("ចម្លង Link ដោយដៃ៖", shareUrl);
          }
        }
      }

      const ipaInput = document.getElementById("ipa-file-input");
      const dropZoneIdle = document.getElementById("drop-zone-idle");
      const fileInfo = document.getElementById("file-info");
      const fileName = document.getElementById("file-name");
      const fileSize = document.getElementById("file-size");
      const removeBtn = document.getElementById("remove-file-btn");

      if (ipaInput) {
        ipaInput.addEventListener("change", (e) => {
          if (e.target.files.length > 0) {
            const f = e.target.files[0];
            fileName.textContent = f.name;
            fileSize.textContent = (f.size / (1024 * 1024)).toFixed(2) + " MB";
            dropZoneIdle.classList.add("hidden");
            fileInfo.classList.remove("hidden");
          }
        });
      }

      if (removeBtn) {
        removeBtn.addEventListener("click", (e) => {
          e.preventDefault();
          ipaInput.value = "";
          dropZoneIdle.classList.remove("hidden");
          fileInfo.classList.add("hidden");
        });
      }

      const p12Input = document.getElementById("p12-file-input");
      const p12Name = document.getElementById("p12-name");
      if (p12Input) {
        p12Input.addEventListener("change", (e) => {
          if (e.target.files.length > 0) {
            p12Name.textContent = e.target.files[0].name;
            p12Name.classList.add("font-bold");
          }
        });
      }

      const provInput = document.getElementById("prov-file-input");
      const provName = document.getElementById("prov-name");
      if (provInput) {
        provInput.addEventListener("change", (e) => {
          if (e.target.files.length > 0) {
            provName.textContent = e.target.files[0].name;
            provName.classList.add("font-bold");
          }
        });
      }

      const iconInput = document.getElementById("icon-file-input");
      const iconName = document.getElementById("icon-name");
      if (iconInput) {
        iconInput.addEventListener("change", (e) => {
          if (e.target.files.length > 0) {
            iconName.textContent = e.target.files[0].name;
            iconName.classList.add("font-bold");
          }
        });
      }

      const tweakInput = document.getElementById("tweak-file-input");
      const tweakName = document.getElementById("tweak-name");
      if (tweakInput) {
        tweakInput.addEventListener("change", (e) => {
          if (e.target.files.length > 0) {
            tweakName.textContent = e.target.files[0].name;
            tweakName.classList.add("font-bold");
          }
        });
      }

      const sharedLogoEl = document.getElementById("shared-app-logo");
      if (sharedLogoEl) {
        sharedLogoEl.addEventListener("error", function () {
          const fallbackSrc = this.getAttribute("data-fallback");
          if (fallbackSrc && this.src !== fallbackSrc) {
            this.src = fallbackSrc;
          }
        });
      }

      window.addEventListener("DOMContentLoaded", () => {
        const urlParams = new URLSearchParams(window.location.search);
        const sharedJobId = urlParams.get("job_id");
        if (sharedJobId) {
          lastGeneratedJobId = sharedJobId;
          const normalContainer = document.getElementById(
            "normal-app-container",
          );
          if (normalContainer) normalContainer.style.display = "none";

          const footerSection = document.getElementById("main-footer-section");
          if (footerSection) footerSection.style.display = "none";

          const sharedView = document.getElementById("shared-install-view");
          if (sharedView) sharedView.classList.remove("hidden");

          const origin = getCurrentOrigin(false);
          const manifestOrigin = getCurrentOrigin(true);
          const manifestUrl =
            manifestOrigin +
            "/manifest.plist?job_id=" +
            encodeURIComponent(sharedJobId);
          document.getElementById("shared-install-btn").href =
            "itms-services://?action=download-manifest&url=" +
            encodeURIComponent(manifestUrl);

          fetch(
            "/job-info?job_id=" +
              encodeURIComponent(sharedJobId) +
              "&_=" +
              Date.now(),
            { cache: "no-store" },
          )
            .then((res) => res.json())
            .then((data) => {
              if (data && data.status === "success") {
                const appTitle =
                  data.title ||
                  data.app_name ||
                  data.display_name ||
                  data.name ||
                  "";
                if (appTitle) {
                  document.getElementById("shared-app-title").textContent =
                    appTitle;
                }
                const rawIcon = data.icon_url || data.icon || "";
                if (rawIcon && sharedLogoEl) {
                  const iconHref = rawIcon.startsWith("http")
                    ? rawIcon
                    : origin + (rawIcon.startsWith("/") ? "" : "/") + rawIcon;
                  sharedLogoEl.src =
                    iconHref +
                    (iconHref.includes("?") ? "&" : "?") +
                    "_t=" +
                    Date.now();
                }
              }
            })
            .catch(() => {});
        }
      });

      const signForm = document.getElementById("sign-form");
      const progressBarFill = document.getElementById("progress-bar-fill");
      const progressPercent = document.getElementById("progress-percent");
      const statusLabel = document.getElementById("status-label");
      const successBox = document.getElementById("success-message-box");

      if (signForm) {
        signForm.addEventListener("submit", (e) => {
          e.preventDefault();
          stopAllSignNetwork();
          hideAdminKeyBoxAlert();

          if (currentSource === "upload" && !ipaInput.files.length) {
            alert("សូមជ្រើសរើសហ្វាល IPA!");
            return;
          }
          if (
            currentSource === "preset" &&
            !document.getElementById("preset-ipa-select").value
          ) {
            alert("សូមជ្រើសរើស App ស្រាប់!");
            return;
          }

          const retentionModeEl = document.getElementById(
            "retention-mode-select",
          );
          const adminKeyEl = document.getElementById("admin-key-input");
          if (retentionModeEl && retentionModeEl.value === "permanent") {
            const keyVal = (adminKeyEl ? adminKeyEl.value : "").trim();
            if (!keyVal) {
              if (adminKeyEl) adminKeyEl.focus();
              showAdminKeyBoxAlert(
                "មិនទាន់មាន Key ទេ! សូម Chat ទៅ Admin ដើម្បីយក Key។",
                ADMIN_TELEGRAM_URL,
              );
              return;
            }
          }

          const myRunId = ++activeRunId;
          let maxPercentSeen = 0;
          currentSigningJobId = "";

          const formData = new FormData(signForm);
          let signDeviceId = "";
          try {
            signDeviceId = localStorage.getItem("chek_signer_device_id") || "";
            if (!signDeviceId) {
              signDeviceId =
                "DEV-" +
                Math.random().toString(36).substring(2, 10).toUpperCase();
              localStorage.setItem("chek_signer_device_id", signDeviceId);
            }
          } catch (e) {
            signDeviceId = "DEV-WEB";
          }
          formData.append("device_id", signDeviceId);

          if (currentSource === "upload") {
            formData.delete("preset_ipa");
          } else {
            formData.delete("ipa_file");
          }

          activeSignAbort = new AbortController();
          setSignButtonBusy(true);
          progressBarFill.style.width = "0%";
          progressPercent.textContent = "0.00%";
          statusLabel.textContent = "ស្ថានភាព៖ កំពុង Sign...";
          successBox.classList.add("hidden");

          fetch("/sign", {
            method: "POST",
            body: formData,
            cache: "no-store",
            signal: activeSignAbort.signal,
          })
            .then((res) => res.text())
            .then((rawText) => {
              if (myRunId !== activeRunId) return;
              activeSignAbort = null;

              let data = null;
              try {
                data = JSON.parse(rawText);
              } catch (err) {
                setSignButtonBusy(false);
                statusLabel.textContent = "ស្ថានភាព៖ បរាជ័យ";
                alert(cleanZsignError(rawText || "Server error"));
                return;
              }

              if (data.status === "error") {
                setSignButtonBusy(false);
                statusLabel.textContent = "ស្ថានភាព៖ បរាជ័យ";
                if (
                  data.code === "MISSING_ADMIN_KEY" ||
                  data.code === "INVALID_ADMIN_KEY"
                ) {
                  if (adminKeyEl) adminKeyEl.focus();
                  showAdminKeyBoxAlert(
                    data.code === "MISSING_ADMIN_KEY"
                      ? "មិនទាន់មាន Key ទេ! សូម Chat ទៅ Admin ដើម្បីយក Key។"
                      : "ដាក់ Key ខុស ឬបរាជ័យ! សូម Chat ទៅ Admin ដើម្បីយក Key។",
                    data.telegram_url || ADMIN_TELEGRAM_URL,
                  );
                } else {
                  alert(cleanZsignError(data.message || "Sign error"));
                }
                return;
              }

              const activeJobId = data.job_id || "";
              if (!activeJobId) {
                setSignButtonBusy(false);
                statusLabel.textContent = "ស្ថានភាព៖ បរាជ័យ";
                alert("Missing job_id");
                return;
              }

              currentSigningJobId = activeJobId;

              activePollTimer = setInterval(() => {
                if (myRunId !== activeRunId) {
                  stopAllSignNetwork();
                  return;
                }

                activePollAbort = new AbortController();
                fetch(
                  "/progress?job_id=" +
                    encodeURIComponent(activeJobId) +
                    "&_=" +
                    Date.now(),
                  {
                    cache: "no-store",
                    signal: activePollAbort.signal,
                  },
                )
                  .then((r) => r.text())
                  .then((pText) => {
                    if (myRunId !== activeRunId) return;
                    let prog = null;
                    try {
                      prog = JSON.parse(pText);
                    } catch (err) {
                      return;
                    }
                    if (!prog) return;

                    let pct = Number(prog.percent || 0);
                    if (
                      prog.status !== "error" &&
                      prog.status !== "cancelled"
                    ) {
                      if (pct < maxPercentSeen) {
                        pct = maxPercentSeen;
                      } else {
                        maxPercentSeen = pct;
                      }
                    } else {
                      pct = 0;
                    }

                    progressBarFill.style.width = pct + "%";
                    progressPercent.textContent = pct.toFixed(2) + "%";
                    statusLabel.textContent =
                      "ស្ថានភាព៖ " + (prog.message || "");

                    if (prog.status === "cancelled") {
                      stopAllSignNetwork();
                      currentSigningJobId = "";
                      progressBarFill.style.width = "0%";
                      progressPercent.textContent = "0.00%";
                      statusLabel.textContent =
                        "ស្ថានភាព៖ បានបោះបង់ (Cancelled)";
                      setSignButtonBusy(false);
                    } else if (prog.status === "error") {
                      stopAllSignNetwork();
                      currentSigningJobId = "";
                      setSignButtonBusy(false);
                      statusLabel.textContent = "ស្ថានភាព៖ បរាជ័យ";
                      alert(cleanZsignError(prog.message || "Signing failed"));
                    } else if (prog.status === "done" || pct >= 100) {
                      stopAllSignNetwork();
                      currentSigningJobId = "";
                      setSignButtonBusy(false);
                      progressBarFill.style.width = "100%";
                      progressPercent.textContent = "100.00%";
                      statusLabel.textContent = "ស្ថានភាព៖ រួចរាល់";
                      successBox.classList.remove("hidden");

                      const doneJobId = prog.job_id || activeJobId;
                      lastGeneratedJobId = doneJobId;
                      lastGeneratedFilename = prog.filename || "";

                      const origin = getCurrentOrigin(false);
                      const manifestOrigin = getCurrentOrigin(true);

                      const downloadUrl =
                        origin +
                        "/output/" +
                        encodeURIComponent(prog.filename || "");
                      const dlBtn = document.getElementById(
                        "download-signed-ipa",
                      );
                      dlBtn.href = downloadUrl;
                      if (prog.filename) {
                        dlBtn.setAttribute("download", prog.filename);
                      }

                      const manifestUrl =
                        manifestOrigin +
                        "/manifest.plist?job_id=" +
                        encodeURIComponent(doneJobId);
                      document.getElementById("install-app-btn").href =
                        "itms-services://?action=download-manifest&url=" +
                        encodeURIComponent(manifestUrl);
                    }
                  })
                  .catch(() => {});
              }, 800);
            })
            .catch((err) => {
              activeSignAbort = null;
              if (err && err.name === "AbortError") return;
              if (myRunId !== activeRunId) return;
              setSignButtonBusy(false);
              statusLabel.textContent = "ស្ថានភាព៖ បរាជ័យ";
              alert("Network error while signing");
            });
        });
      }

      async function clearAllSignedData() {
        const ok = confirm(
          "តើលោកបងពិតជាចង់លុបហ្វាល IPA និង Link ដែលបាន Sign រួចទាំងអស់មែនទេ?",
        );
        if (!ok) return;

        try {
          const res = await fetch("/clear-all", { method: "POST" });
          const data = await res.json();
          if (data.status === "success") {
            alert(data.message);
            location.reload();
          } else {
            alert(data.message || "មិនអាចលុបបានទេ");
          }
        } catch (err) {
          alert("មានបញ្ហាបណ្តាញពេលលុបទិន្នន័យ");
        }
      }
    </script>
  </body>
</html>
```[cite: 18]

ប្រសិនបើពេល push កូដថ្មីនេះឡើង Railway ហើយលោកបងសាក sign IPA ម្ដងទៀត ហើយនៅតែឃើញសារ error អ្វីបន្ថែម ថតរូបសារ error នោះផ្ញើមកឱ្យខ្ញុំ ខ្ញុំនឹងជួយមើលបន្តភ្លាម។
