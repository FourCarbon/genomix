# Genomix — ThreatScan URL Checker (Demo)

Simple Flask demo that accepts a pasted URL, queries a scan provider, and returns a short prewritten verdict (Safe / Spam/Phishing / Malicious).

## Files
- `app.py` — Flask backend (API endpoint: `/api/analyze`)
- `templates/vfx.html` — Frontend UI (paste a URL and click "Check")
- `requirements.txt` — Python dependencies
- `.env.example` — Example environment file (DO NOT store real keys in the repo)

## Quick start (local)
1. Create a virtual environment and activate:
   - `python -m venv venv`
   - macOS / Linux: `source venv/bin/activate`
   - Windows: `venv\Scripts\activate`

2. Install dependencies:
   - `pip install -r requirements.txt`

3. Add your API key:
   - Copy `.env.example` → `.env` locally and set:
     ```
     THREATSCAN_API_KEY=your_real_api_key_here
     ```
   - DO NOT commit `.env` to the repository.

4. Run the app:
   - `python app.py`
   - Open: http://127.0.0.1:5000

## Notes & security
- Keep the API key secret (use environment variables, CI secrets, or a secrets manager).
- The provider's public API is rate-limited. Consider caching results in production.
- This is a demo; treat results as advisory and not a substitute for full threat investigation.

## License
Add your preferred license if you want to make the project public.
