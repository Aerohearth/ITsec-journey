# SocForge — Web App

## Running locally

### 1. Install backend dependencies

```bash
pip install -r backend/requirements.txt
```

Or if the project root dependencies are already installed:

```bash
pip install fastapi "uvicorn[standard]"
```

### 2. Start the backend

Run from the project root:

```bash
uvicorn backend.main:app --reload
```

Backend runs at `http://localhost:8000`.  
Interactive API docs: `http://localhost:8000/docs`

### 3. Open the frontend

Open `frontend/index.html` directly in your browser, or serve it over HTTP:

```bash
cd frontend && python3 -m http.server 3000
```

Then visit `http://localhost:3000`.

> **Note:** Opening the file directly (`file://`) works for all features. Serving over HTTP is required for the PWA install prompt.

### 4. API Key

On first launch you'll be prompted for your Anthropic API key (`sk-ant-…`).  
Get one at [console.anthropic.com](https://console.anthropic.com).

Your key is stored in `localStorage` and sent as an `X-Api-Key` header to the local backend only — it never leaves your machine.

---

## Architecture

```
/
├── backend/
│   ├── main.py          FastAPI app — all 11 API endpoints
│   └── requirements.txt
├── frontend/
│   ├── index.html       Single-file SPA — no frameworks, no build step
│   ├── manifest.json    PWA manifest
│   └── sw.js            Service worker (offline shell cache)
├── main.py              Original CLI app (unchanged)
└── ...
```

The CLI (`python main.py`) and web app (`uvicorn backend.main:app`) are independent — both work without touching each other.

## PWA Install

Once the frontend is served over HTTP and the backend is running, Chrome/Edge will show an install prompt in the address bar. Click it to install SocForge as a standalone app on your desktop or home screen.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/briefing` | Streams daily threat briefing |
| GET | `/api/cves` | Recent critical CVEs (NVD) |
| POST | `/api/cves/analyze` | Streams CVE deep-dive |
| GET | `/api/exploits` | Active KEV entries (CISA) |
| POST | `/api/exploits/analyze` | Streams KEV entry analysis |
| POST | `/api/threathunt` | Streams threat hunt scenario |
| POST | `/api/explain` | Streams concept explanation |
| POST | `/api/quiz` | Streams knowledge quiz |
| GET | `/api/kevstats` | Full KEV catalog + stats |
| GET | `/api/iris/scenarios` | IRIS scenario list |
| POST | `/api/iris` | Streams IRIS multi-turn response |
| GET | `/api/health` | Health check |
