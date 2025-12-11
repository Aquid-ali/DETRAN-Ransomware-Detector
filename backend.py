import os
import json
import math
import subprocess
import logging
import shutil
import random
from pathlib import Path

from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import requests
import datetime
import json
from datetime import datetime
from zoneinfo import ZoneInfo  # Python 3.9+



# Optional imports
try:
    import pyclamd
    CLAMD_AVAILABLE = True
except:
    CLAMD_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except:
    YARA_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except:
    MAGIC_AVAILABLE = False


# =========================================
# LOAD ENV + CONFIG
# =========================================
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_API_URL = os.getenv("GEMINI_API_URL")

BASE_DIR = Path.cwd()
UPLOAD_FOLDER = BASE_DIR / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)
QUARANTINE_FOLDER = BASE_DIR / "quarantine"
QUARANTINE_FOLDER.mkdir(exist_ok=True)


app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)
app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("backend")
LOG_FILE = BASE_DIR / "deletion_logs.jsonl"

IST = ZoneInfo("Asia/Kolkata")
LOG_FILE = BASE_DIR / "deletion_logs.jsonl"



# =========================================
# CHATBOT - GEMINI SETUP
# =========================================
def call_gemini(user_message):
    system_prompt = (
    "You are DETRAN AI — a cybersecurity assistant for the DETRAN ransomware detection platform. "
    "KEY INSTRUCTIONS:\n"
    "1. Keep responses BRIEF and TECHNICAL - maximum 2-3 sentences\n"
    "2. NO initial greetings or lengthy introductions\n"
    "3. For 'hi' or 'hello' respond ONLY with: 'Hi, how can I help with ransomware detection?'\n"
    "4. Focus on DETRAN's specific features:\n"
    "   - AI-powered file scanning for ransomware\n"
    "   - YARA rule-based threat detection\n"
    "   - Real-time protection monitoring\n"
    "   - File quarantine and remediation\n"
    "   - Detailed security reports\n"
    "5. DETRAN Platform Overview:\n"
    "   - Advanced ransomware detection using machine learning\n"
    "   - Scans files for encryption patterns and suspicious behavior\n"
    "   - Provides instant threat analysis and security recommendations\n"
    "   - Supports multiple file types with secure processing\n"
    "   - Is able to quarantine and delete the suspicious files by asking users\n"
    "   - Provides logs about the scanned files, deleted files and quarantined files\n"
    "6. Never provide code, exploit details, or hacking techniques\n"
    "7. If unsure, direct users to upload files for scanning\n"
    "8. Always stay on-topic about cybersecurity and ransomware protection\n"
    "9. Provide users with email id and phone number if they ask which is at the bottom of home page\n"
    "10.CEO of DETRAN is Aquid Ali and my phone number is 8150081020, Give them only if they ask"
)

    payload = {
        "contents": [
            {
                "parts": [
                    {
                        "text": system_prompt + "\n\nUser: " + user_message
                    }
                ]
            }
        ]
    }

    endpoint = f"{GEMINI_API_URL}?key={GEMINI_API_KEY}"
    resp = requests.post(endpoint, json=payload, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]
    except:
        return json.dumps(data)


# =========================================
# YARA RULES
# =========================================
YARA_RULES = r"""
rule RansomNoteGeneric
{
    strings:
        $text1 = "YOUR FILES ARE ENCRYPTED" nocase
        $text2 = "restore-files" nocase
        $text3 = "decrypt" nocase
        $text4 = "ransom" nocase
    condition:
        any of them
}
"""

compiled_yara = None
if YARA_AVAILABLE:
    try:
        compiled_yara = yara.compile(source=YARA_RULES)
        log.info("YARA loaded.")
    except Exception as e:
        log.warning("YARA failed: %s", e)
        compiled_yara = None

# =========================================
# CLAMAV
# =========================================
clamd_client = None
CLAMSCAN_BIN = shutil.which("clamscan") or shutil.which("clamdscan")

if CLAMD_AVAILABLE:
    try:
        clamd_client = pyclamd.ClamdAgnostic()
        clamd_client.ping()
        log.info("ClamAV daemon available.")
    except:
        log.info("ClamAV daemon not active. Using clamscan.")
else:
    log.info("pyclamd not installed.")


# =========================================
# HELPERS
# =========================================
def shannon_entropy(data: bytes):
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def is_high_entropy(path, threshold=7.5):
    try:
        size = os.path.getsize(path)
        if size < 200:
            return False, 0.0

        with open(path, "rb") as f:
            chunk = f.read(65536)

        ent = shannon_entropy(chunk)
        return ent >= threshold, round(ent, 3)

    except:
        return False, 0.0


def clam_scan(path):
    try:
        if clamd_client:
            res = clamd_client.scan_file(str(path))
            if isinstance(res, dict):
                for _, val in res.items():
                    if val[0] == "FOUND":
                        return True
            return False

        if CLAMSCAN_BIN:
            proc = subprocess.run([CLAMSCAN_BIN, "--no-summary", str(path)],
                                  capture_output=True, text=True)
            return "FOUND" in proc.stdout

        return False

    except:
        return False


def yara_check(path):
    if not compiled_yara:
        return False
    try:
        matches = compiled_yara.match(str(path))
        return isinstance(matches, list) and len(matches) > 0
    except:
        return False


def file_type(path):
    if MAGIC_AVAILABLE:
        try:
            m = magic.Magic(mime=True)
            return m.from_file(str(path))
        except:
            return Path(path).suffix.lower()
    return Path(path).suffix.lower()


# >>>> NEW: secure delete helper (overwrite then remove)
def _is_within_uploads(path: Path):
    try:
        # Prevent path traversal - ensure real path is within UPLOAD_FOLDER
        return str(path.resolve()).startswith(str(UPLOAD_FOLDER.resolve()) + os.sep)
    except Exception:
        return False


def secure_delete(path: Path, passes: int = 1):
    """
    Overwrite file contents with random bytes 'passes' times then remove file.
    Only operates on files within UPLOAD_FOLDER for safety.
    Returns True if deletion happened, False otherwise.
    """
    try:
        if not path.exists() or not path.is_file():
            return False

        if not _is_within_uploads(path):
            log.warning("Attempt to delete outside uploads folder: %s", path)
            return False

        size = path.stat().st_size
        # Overwrite with random data `passes` times (default 1)
        with open(path, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                remaining = size
                # write in chunks to avoid memory blowup
                while remaining > 0:
                    chunk_size = min(65536, remaining)
                    f.write(os.urandom(chunk_size))
                    remaining -= chunk_size
                f.flush()
                os.fsync(f.fileno())

        # Finally remove
        path.unlink()
        log.info("Secure-deleted: %s", path)
        return True
    except Exception as e:
        log.exception("secure_delete failed for %s: %s", path, e)
        return False
# <<<< end new


# =========================================
# SCAN FILE
# =========================================
def scan_file(path):
    path = Path(path)
    report = {
        "file": path.name,
        "path": str(path),
        "file_type": file_type(path),
        "clamav": False,
        "yara": False,
        "high_entropy": False,
        "entropy_value": 0.0,
        "infected": False
    }

    c = clam_scan(path)
    report["clamav"] = c
    if c: report["infected"] = True

    y = yara_check(path)
    report["yara"] = y
    if y: report["infected"] = True

    h, ent = is_high_entropy(path)
    report["high_entropy"] = h
    report["entropy_value"] = ent
    if h: report["infected"] = True

    return report


# =========================================
# ROUTES
# =========================================

@app.route("/")
def home():
    return app.send_static_file("index.html")


@app.route("/scan.html")
def scan_page():
    return app.send_static_file("scan.html")


# Chatbot API
@app.route("/api/chat", methods=["POST"])
def chat():
    msg = request.json.get("message", "").strip()
    if not msg:
        return jsonify({"error": "Message required"}), 400

    try:
        reply = call_gemini(msg)
        return jsonify({"reply": reply})
    except Exception as e:
        return jsonify({"error": "Gemini request failed", "detail": str(e)}), 500


# Upload
@app.route("/upload", methods=["POST"])
def upload():
    saved = []
    for file in request.files.getlist("file"):
        filename = os.path.basename(file.filename)
        target = UPLOAD_FOLDER / filename
        file.save(str(target))
        saved.append(filename)
        log.info("Uploaded: %s", filename)
    return jsonify({"saved": saved})


# Scan specific files
@app.route("/scan_selected", methods=["POST"])
def scan_selected():
    files = request.json.get("files", [])
    summary = {"scanned_files": 0, "infected_count": 0, "files": []}

    for file in files:
        path = UPLOAD_FOLDER / os.path.basename(file)
        if not path.exists():
            continue

        result = scan_file(path)
        summary["files"].append(result)
        summary["scanned_files"] += 1
        if result["infected"]:
            summary["infected_count"] += 1

    # >>>> NEW: If infected files found, include list for front-end to ask user for deletion
    infected_files = [f["file"] for f in summary["files"] if f.get("infected")]
    if infected_files:
        summary["deletion_recommended"] = True
        summary["deletable_files"] = infected_files
        summary["message"] = (
            "Infected or suspicious files detected. Recommend deletion. "
            "Call POST /delete_files with {'files': [...], 'confirm': true} to securely remove them."
        )
    else:
        summary["deletion_recommended"] = False
        summary["deletable_files"] = []

    return jsonify(summary)


# Scan all uploaded files
@app.route("/scan_all", methods=["GET"])
def scan_all():
    summary = {"scanned_files": 0, "infected_count": 0, "files": []}

    for file in os.listdir(UPLOAD_FOLDER):
        path = UPLOAD_FOLDER / file
        if not path.is_file():
            continue

        result = scan_file(path)
        summary["files"].append(result)
        summary["scanned_files"] += 1
        if result["infected"]:
            summary["infected_count"] += 1

    # >>>> NEW: If infected files found, include list for front-end to ask user for deletion
    infected_files = [f["file"] for f in summary["files"] if f.get("infected")]
    if infected_files:
        summary["deletion_recommended"] = True
        summary["deletable_files"] = infected_files
        summary["message"] = (
            "Infected or suspicious files detected. Recommend deletion. "
            "Call POST /delete_files with {'files': [...], 'confirm': true} to securely remove them."
        )
    else:
        summary["deletion_recommended"] = False
        summary["deletable_files"] = []

    return jsonify(summary)

def append_deletion_logs(deleted_files):
    """
    Append deletion records to LOG_FILE as JSON lines.
    Each entry: {"file": "<name>", "deleted_at": "<IST ISO timestamp>"}
    """
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        # Current time in IST
        now_ist = datetime.now(IST).isoformat(timespec="seconds")
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            for fname in deleted_files:
                fh.write(json.dumps({
                    "file": fname,
                    "deleted_at": now_ist
                }) + "\n")
        return True
    except Exception as e:
        log.exception("Failed writing deletion logs: %s", e)
        return False


# >>>> NEW: Endpoint to quarantine files (move from uploads to quarantine folder)
@app.route("/quarantine_files", methods=["POST"])
def quarantine_files():
    """
    Expect JSON:
    {
        "files": ["a.exe", "b.docx"],
        "confirm": true
    }
    This will move each file from UPLOAD_FOLDER to QUARANTINE_FOLDER.
    """
    body = request.get_json(force=True, silent=True) or {}
    files = body.get("files", [])
    confirm = body.get("confirm", False)

    if not isinstance(files, list) or not files:
        return jsonify({"error": "Provide non-empty 'files' list"}), 400
    if not confirm:
        return jsonify({"error": "Quarantine not confirmed. Set 'confirm': true to proceed."}), 400

    quarantined = []
    failed = []

    for fname in files:
        safe_name = os.path.basename(fname)
        src_path = UPLOAD_FOLDER / safe_name
        dst_path = QUARANTINE_FOLDER / safe_name

        if not src_path.exists() or not src_path.is_file():
            failed.append({"file": safe_name, "reason": "not found"})
            continue

        # Only allow quarantine if inside uploads dir
        if not _is_within_uploads(src_path):
            failed.append({"file": safe_name, "reason": "outside uploads directory"})
            continue

        try:
            # If a file with same name already exists in quarantine, add a suffix
            if dst_path.exists():
                stem = dst_path.stem
                ext = dst_path.suffix
                counter = 1
                while True:
                    new_name = f"{stem}_q{counter}{ext}"
                    new_dst = QUARANTINE_FOLDER / new_name
                    if not new_dst.exists():
                        dst_path = new_dst
                        break
                    counter += 1

            shutil.move(str(src_path), str(dst_path))
            quarantined.append(str(dst_path.name))
            log.info("Quarantined %s -> %s", src_path, dst_path)
        except Exception as e:
            log.exception("Failed to quarantine %s: %s", src_path, e)
            failed.append({"file": safe_name, "reason": "quarantine_failed"})

    return jsonify({
        "quarantined": quarantined,
        "failed": failed,
        "summary": {
            "requested": len(files),
            "quarantined_count": len(quarantined),
            "failed_count": len(failed)
        }
    })



# >>>> NEW: Endpoint to securely delete files (must be in uploads folder)
@app.route("/delete_files", methods=["POST"])
def delete_files():
    """
    Expect JSON:
    {
        "files": ["a.exe", "b.docx"],
        "confirm": true
    }
    This will securely overwrite and remove each file inside UPLOAD_FOLDER.
    """
    body = request.get_json(force=True, silent=True) or {}
    files = body.get("files", [])
    confirm = body.get("confirm", False)

    if not isinstance(files, list) or not files:
        return jsonify({"error": "Provide non-empty 'files' list"}), 400
    if not confirm:
        return jsonify({"error": "Deletion not confirmed. Set 'confirm': true to proceed."}), 400

    deleted = []
    failed = []

    for fname in files:
        # sanitize and confine to uploads folder
        safe_name = os.path.basename(fname)
        path = UPLOAD_FOLDER / safe_name

        if not path.exists() or not path.is_file():
            failed.append({"file": safe_name, "reason": "not found"})
            continue

        # only allow deletion if inside uploads dir
        if not _is_within_uploads(path):
            failed.append({"file": safe_name, "reason": "outside uploads directory"})
            continue

        ok = secure_delete(path, passes=1)
        if ok:
            deleted.append(safe_name)
        else:
            failed.append({"file": safe_name, "reason": "delete_failed"})

        # Log successful deletions
        if deleted:
            append_deletion_logs(deleted)


    return jsonify({
        "deleted": deleted,
        "failed": failed,
        "summary": {
            "requested": len(files),
            "deleted_count": len(deleted),
            "failed_count": len(failed)
        }
    })

@app.route("/logs", methods=["GET"])
def get_logs():
    """
    Returns deletion logs as JSON list.
    Query params:
      - limit (int, optional) -> last N entries (default: all)
    """
    limit = request.args.get("limit", type=int)
    if not LOG_FILE.exists():
        return jsonify({"logs": []})

    entries = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except Exception:
                    continue
        # newest last -> reverse to show newest first
        entries = entries[::-1]
        if limit and limit > 0:
            entries = entries[:limit]
        return jsonify({"logs": entries})
    except Exception as e:
        log.exception("Failed reading logs: %s", e)
        return jsonify({"error": "failed to read logs"}), 500



# =========================================
# RUN SERVER
# =========================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
