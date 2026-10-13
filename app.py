# app.py
import os
import time
import re
import requests
from urllib.parse import urlparse
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")
if not VT_API_KEY:
    raise RuntimeError("Please set the VIRUSTOTAL_API_KEY environment variable (see .env.example)")

VT_BASE = "https://www.virustotal.com/api/v3"

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

# helper: validate url basic
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

# helper: pool VT analysis until completed
def vt_post_url(url):
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": url}
    resp = requests.post(f"{VT_BASE}/urls", headers=headers, data=data, timeout=15)
    resp.raise_for_status()
    return resp.json()  # contains data.id (analysis id encoded)

def vt_get_analysis(analysis_id):
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(f"{VT_BASE}/analyses/{analysis_id}", headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()

def vt_get_url_object(encoded_url_id):
    headers = {"x-apikey": VT_API_KEY}
    resp = requests.get(f"{VT_BASE}/urls/{encoded_url_id}", headers=headers, timeout=15)
    resp.raise_for_status()
    return resp.json()

# Parse VT analysis to a summary object
def interpret_vt_response(analysis_json, url_object_json=None):
    """
    Return dict: {severity: 'safe'|'suspicious'|'malicious', score: int, reasons: list, family: str|None, summary: str}
    Logic:
      - Prefer analysis.attributes.stats if available (malicious / suspicious counts).
      - Inspect last_analysis_results: check engine results for keywords.
    """
    stats = {}
    reasons = []
    family = None
    score = 0
    severity = "safe"

    # Collect stats from analysis (if present)
    if analysis_json and isinstance(analysis_json.get("data", {}).get("attributes", {}).get("stats", {}), dict):
        stats = analysis_json["data"]["attributes"]["stats"]

    # If we have a URL object (more complete last_analysis_results)
    last_results = None
    if url_object_json:
        last_results = url_object_json.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

    # fallback: sometimes analysis results are in analysis_json.data.attributes.results
    if not last_results:
        last_results = analysis_json.get("data", {}).get("attributes", {}).get("results", {})

    malicious_count = 0
    suspicious_count = 0
    if stats:
        malicious_count = stats.get("malicious", 0)
        suspicious_count = stats.get("suspicious", 0)
        # set score roughly
        score = malicious_count * 2 + suspicious_count

    # Scanning engine textual detections
    detected_keywords = set()
    if isinstance(last_results, dict):
        for engine, info in last_results.items():
            category = info.get("category", "") or ""
            result_text = (info.get("result") or "") or ""
            # record counts from category if present
            if category.lower() == "malicious":
                malicious_count += 1
            if category.lower() == "suspicious":
                suspicious_count += 1
            # inspect result text for families and keywords
            text = f"{engine} {result_text}".lower()
            for k in ["trojan", "ransom", "spyware", "adware", "phish", "miner", "cryptominer", "spam", "dropper", "malware", "backdoor", "exploit"]:
                if k in text:
                    detected_keywords.add(k)
                    reasons.append(f"{engine}: {result_text}")
            # try to pick family name if given (some engines provide families)
            if info.get("result"):
                family = info.get("result")  # naive, override later if better

    # Decide severity
    if malicious_count > 0:
        severity = "malicious"
    elif suspicious_count > 0 or len(detected_keywords) > 0:
        # treat phishing/spam specially if no malicious
        if any(k in detected_keywords for k in ("phish", "spam")) and malicious_count == 0:
            severity = "suspicious"  # orange
        else:
            # when there are suspicious counts but no malicious
            severity = "suspicious"
    else:
        severity = "safe"

    # determine predominant family/category
    family_guess = None
    for priority in ("ransom", "trojan", "spyware", "adware", "phish", "miner", "spam", "malware"):
        if any(priority in k for k in detected_keywords):
            family_guess = priority
            break
    if not family_guess and family:
        # normalize family token
        f = family.lower()
        for known in PREWRITTEN_SUMMARIES:
            if known in f:
                family_guess = known
                break

    if not family_guess:
        family_guess = "unknown"

    # Pick prewritten summary
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
        # POST /urls -> returns data.id like "analyzed_url_id"
        post_resp = vt_post_url(url)
        analysis_id = post_resp.get("data", {}).get("id")
        if not analysis_id:
            return jsonify({"error": "VirusTotal did not return an analysis id."}), 500

        # Poll for analysis completion
        timeout_seconds = 25
        start = time.time()
        analysis_json = None
        while True:
            analysis_json = vt_get_analysis(analysis_id)
            status = analysis_json.get("data", {}).get("attributes", {}).get("status")
            if status == "completed":
                break
            if time.time() - start > timeout_seconds:
                # Try to still fetch URL object (might have partial results)
                break
            time.sleep(1.5)

        # To get aggregated results / last_analysis_results, fetch URL object
        # The URL object id is encoded in a different way: You can pass VT's encoded id from the POST 'data.id' returned for urls: sometimes analysis POST returns id for analysis, while POST /urls returns location to resource.
        # Try to read encoded_url from analysis_json if available
        encoded_url_id = None
        # analysis_json.data.attributes may include 'result' or 'url' resource links
        # Safer approach: call vt_get_url_object with url-encoded id via VT endpoint that encodes the URL:
        # According to VT docs: to get URL object, you encode the url with base64-url replacement. But simpler: call vt_post_url returned 'data.id' sometimes is url id for /urls
        # We'll attempt to get a url object by encoding the URL as VT expects:
        import base64
        encoded = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        encoded_url_id = encoded

        url_object_json = None
        try:
            url_object_json = vt_get_url_object(encoded_url_id)
        except Exception:
            # fallback: try reading a 'result' link in analysis_json
            url_object_json = None

        interpreted = interpret_vt_response(analysis_json or {}, url_object_json)

        # Construct client payload
        payload = {
            "url": url,
            "status": interpreted["severity"],
            "title": interpreted["title"],
            "summary": interpreted["summary"],
            "malicious_count": interpreted["malicious_count"],
            "suspicious_count": interpreted["suspicious_count"],
            "reasons": interpreted["reasons"],
            "family": interpreted["family"],
            # a short UI hint color
            "color": {"safe": "green", "suspicious": "orange", "malicious": "red"}.get(interpreted["severity"], "gray")
        }
        return jsonify(payload)
    except requests.HTTPError as e:
        return jsonify({"error": f"VirusTotal HTTP error: {e.response.status_code} {e.response.text}"}), 502
    except Exception as exc:
        return jsonify({"error": f"Internal server error: {str(exc)}"}), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
