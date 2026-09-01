# 🛡️ ThreatLens

Simple Streamlit cybersecurity intelligence app using VirusTotal and WHOIS, with Google Gemini explanations for Beginner, Intermediate, or Expert users.

## Files
- `app.py` — UI, validation, orchestration, Gemini prompt/call, results display
- `sources.py` — source functions and `SOURCES` registry
- `requirements.txt` — Python dependencies
- `.gitignore` — prevents common secrets/cache files from being committed
- `.env.example` — example only; no real keys

## Architecture
`app.py` → `sources.py` → `get_virustotal()` / `get_whois()`.

To add a future intelligence source, create one function in `sources.py` and register it in `SOURCES`; the UI/orchestration does not need source-specific changes.

## Run
```bash
pip install -r requirements.txt
streamlit run app.py
```

Enter your VirusTotal and Gemini API keys in the sidebar. They are not hard-coded in the repository.

## Google Colab + Cloudflare Quick Tunnel
```python
!pip -q install -r requirements.txt
!wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -O cloudflared
!chmod +x cloudflared
!nohup streamlit run app.py --server.port 8501 --server.address 0.0.0.0 > streamlit.log 2>&1 &
!nohup ./cloudflared tunnel --url http://localhost:8501 > cloudflare.log 2>&1 &
```
Cloudflare Quick Tunnel does not require an API key.

**Never commit real API keys to GitHub.**
