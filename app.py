import os
import time
import re
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
import base64

load_dotenv()

THREATSCAN_API_KEY = os.environ.get("THREATSCAN_API_KEY")
if not THREATSCAN_API_KEY:
    raise RuntimeError("Please set the THREATSCAN_API_KEY environment variable (see .env.example)")

SCAN_API_BASE = "https://www.virustotal.com/api/v3"  # internal provider endpoint (not shown to users)

app = Flask(__name__, template_folder="templates", static_folder="static")

# Prewritten summaries for known categories/families
PREWRITTEN_SUMMARIES = {
    "trojan": {
        "title": "Trojan Detected",
        "summary": "This URL is associated with trojan-type malware. Trojans usually disguise themselves as legitimate files or pages and can give attackers remote access or steal data. Do not download or run anything from this link.",
    },
    "ransomware": {
        "title": "Ransomware Detected",
        "summary": "Ransomware encrypts files and demands payment to restore them. Accessing or opening content from this URL may result in data loss or infection.",
    },
    "spyware": {
        "title": "Spyware Detected",
        "summary": "Spyware is designed to collect information about you without consent. It can monitor activity or exfiltrate credentials. Avoid this site and do not enter credentials.",
    },
    "adware": {
        "title": "Adware / Unwanted Software",
        "summary": "This URL is associated with adware or potentially unwanted programs. It may lead to intrusive ads, popups, or bundled installations.",
    },
    "phishing": {
        "title": "Phishing / Credential Theft",
        "summary": "This URL appears to be used for phishing — attempting to collect credentials or sensitive information by impersonation. Do not enter passwords or personal information.",
    },
    "miner": {
        "title": "Cryptominer Detected",
        "summary": "This site may attempt to run cryptomining scripts in your browser or push miner downloads, using your device resources without consent.",
    },
    "spam": {
        "title": "Spam / Low Trust",
        "summary": "This URL is associated with spammy behavior, suspicious redirects, or low-trust content. It may also be part of mass advertising or scams.",
    },
    "malware": {
        "title": "Malicious Content",
        "summary": "This URL has been flagged for malicious activity. It may host malware that can harm devices or data. Do not interact with it.",
    },
    "unknown": {
        "title": "Unknown / Suspicious",
        "summary": "This URL has suspicious indicators or inconclusive signals. Treat with caution — avoid clicking until you can verify the source.",
    }
}

URL_REGEX = re.compile(r"^https?://", re.I)
def is_valid_url(url):
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if not URL_REGEX.match(url):
        return False
    try:
        parsed = urlparse(url)
        return bool(parsed.netloc)
    except Exception:
        return False

# API helpers (internal)
def post_url_for_scan(url):
    headers = {"x-apikey": THREATSCAN_API_KEY}
    data = {"url": url}
    resp = requests.post(f"{SCAN_API_BASE}/urls", headers=headers, data=data, timeout=15)
    resp.raise_for_status()
    return resp.json()

def get_scan_analysis(analysis_id):
    headers = {"x-apikey": THREATSCAN_API_KEY}
    resp = requests.get(f"{SCAN_API_BASE}/analyses/{analysis_id}", headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()

def get_url_object(encoded_url_id):
    headers = {"x-apikey": THREATSCAN_API_KEY}
    resp = requests.get(f"{SCAN_API_BASE}/urls/{encoded_url_id}", headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()

def interpret_scan_response(analysis_json, url_object_json=None):
    stats = {}
    reasons = []
    family = None
    score = 0
    severity = "safe"

    if analysis_json and isinstance(analysis_json.get("data", {}).get("attributes", {}).get("stats", {}), dict):
        stats = analysis_json["data"]["attributes"]["stats"]

    last_results = None
    if url_object_json:
        last_results = url_object_json.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

    if not last_results:
        last_results = analysis_json.get("data", {}).get("attributes", {}).get("results", {})

    malicious_count = 0
    suspicious_count = 0
    if stats:
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        score = malicious_count * 2 + suspicious_count

    detected_keywords = set()
    if isinstance(last_results, dict):
        for engine, info in last_results.items():
            category = info.get("category", "") or ""
            result_text = (info.get("result") or "") or ""
            if category.lower() == "malicious":
                malicious_count += 1
            if category.lower() == "suspicious":
                suspicious_count += 1
            text = f"{engine} {result_text}".lower()
            for k in ["trojan", "ransom", "spyware", "adware", "phish", "miner", "cryptominer", "spam", "dropper", "malware", "backdoor", "exploit"]:
                if k in text:
                    detected_keywords.add(k)
                    reasons.append(f"{engine}: {result_text}")
            if info.get("result"):
                family = info.get("result")

    if malicious_count > 0:
        severity = "malicious"
    elif suspicious_count > 0 or len(detected_keywords) > 0:
        if any(k in detected_keywords for k in ("phish", "spam")) and malicious_count == 0:
            severity = "suspicious"
        else:
            severity = "suspicious"
    else:
        severity = "safe"

    family_guess = None
    for priority in ("ransom", "trojan", "spyware", "adware", "phish", "miner", "spam", "malware"):
        if any(priority in k for k in detected_keywords):
            family_guess = priority
            break
    if not family_guess and family:
        f = family.lower()
        for known in PREWRITTEN_SUMMARIES:
            if known in f:
                family_guess = known
                break

    if not family_guess:
        family_guess = "unknown"

    summary_info = PREWRITTEN_SUMMARIES.get(family_guess, PREWRITTEN_SUMMARIES["unknown"])

    final = {
        "severity": severity,
        "score": score,
        "malicious_count": malicious_count,
        "suspicious_count": suspicious_count,
        "reasons": reasons[:6],
        "family": family_guess,
        "title": summary_info["title"],
        "summary": summary_info["summary"],
    }
    return final

@app.route("/")
def index():
    return render_template("vfx.html")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    if not is_valid_url(url):
        return jsonify({"error": "Invalid URL. Please provide an absolute http(s) URL."}), 400

    try:
        post_resp = post_url_for_scan(url)
        analysis_id = post_resp.get("data", {}).get("id")
        if not analysis_id:
            return jsonify({"error": "The scanning provider did not return an analysis id."}), 500

        timeout_seconds = 25
        start = time.time()
        analysis_json = None
        while True:
            analysis_json = get_scan_analysis(analysis_id)
            status = analysis_json.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                break
            if time.time() - start > timeout_seconds:
                break
            time.sleep(1.5)

        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        url_object_json = None
        try:
            url_object_json = get_url_object(encoded)
        except Exception:
            url_object_json = None

        interpreted = interpret_scan_response(analysis_json or {}, url_object_json)

        payload = {
            "url": url,
            "status": interpreted["severity"],
            "title": interpreted["title"],
            "summary": interpreted["summary"],
            "malicious_count": interpreted["malicious_count"],
            "suspicious_count": interpreted["suspicious_count"],
            "reasons": interpreted["reasons"],
            "family": interpreted["family"],
            "color": {"safe": "green", "suspicious": "orange", "malicious": "red"}.get(interpreted["severity"], "gray")
        }
        return jsonify(payload)
    except requests.HTTPError as e:
        return jsonify({"error": f"Scanning provider HTTP error: {e.response.status_code} {e.response.text}"}), 502
    except Exception as exc:
        return jsonify({"error": f"Internal server error: {str(exc)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
