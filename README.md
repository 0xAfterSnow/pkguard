# 🛡 PkgGuard

**npm Supply Chain Security Scanner**

PkgGuard scans your `package.json` against multiple threat intelligence sources in real-time — flagging known malware, CVE vulnerabilities, typosquatted packages, and suspicious publish signals. For every flagged package it suggests the **exact safe version** to upgrade to, sourced directly from OSV advisory data.

---

## Features

- **Known malware / backdoor DB** — curated internal database of real-world npm supply chain attacks
- **OSV advisory integration** — live query against Google's Open Source Vulnerability database for CVEs
- **Typosquat detection** — fuzzy similarity engine against ~50 high-profile npm targets
- **npm metadata checks** — flags newly published packages, single-maintainer packages, and abnormal publish velocity
- **Smart suggestions** — for vulnerable packages, suggests the minimum patched version from OSV; for typosquats, resolves the legitimate package name; warns if latest is also compromised
- **Admin panel** — password-protected panel to manage the tools directory (add/remove entries)

---

## Project Structure

```
pkguard/
├── app.py          # Flask routes & API endpoints
├── scanner.py      # Core scan engine (OSV, typosquat, npm meta, suggestions)
├── database.py     # SQLite schema, seed data, connection helpers
├── data/
│   └── pkguard.db  # Auto-created SQLite database
├── static/
│   ├── main.js     # Frontend logic (scan, render, copy-to-clipboard)
│   └── style.css   # UI styles
├── templates/
│   ├── index.html  # Main scanner UI
│   └── admin.html  # Admin panel
├── .env            # Secrets (not committed)
└── venv/           # Python virtual environment
```

---

## Requirements

- Python 3.11+
- pip

---

## Setup & Running

### 1. Clone the repository

```bash
git clone https://github.com/0xaftersnow/pkguard.git
cd pkguard
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
# venv\Scripts\activate         # Windows
```

### 3. Install dependencies

```bash
pip install flask werkzeug requests python-dotenv
```

### 4. Configure environment variables

Create a `.env` file in the project root (use `.env.example` as a template):

```bash
ADMIN_USERNAME=admin
ADMIN_PASSWORD_HASH=<your_hash>
SECRET_KEY=<your_secret_key>
FLASK_DEBUG=false
PORT=5000
```

Generate values:

```bash
# Password hash
python -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('yourpassword'))"

# Secret key
python -c "import secrets; print(secrets.token_hex(32))"
```

### 5. Run — development

```bash
python app.py
```

App starts at **http://localhost:5000**. The SQLite database is created and seeded automatically on first run.

### 6. Run — production (gunicorn)

```bash
gunicorn wsgi:app --workers 2 --timeout 60 --bind 0.0.0.0:5000
```

---

## Deploying to Render / Railway / Fly.io

All three platforms support `Procfile`-based deployments. The repo includes a ready-made `Procfile`:

```
web: gunicorn wsgi:app --workers 2 --timeout 60 --bind 0.0.0.0:$PORT
```

### Render (recommended — free tier available)

1. Push the repo to GitHub
2. New Web Service → connect your repo
3. **Build command:** `pip install -r requirements.txt`
4. **Start command:** `gunicorn wsgi:app --workers 2 --timeout 60 --bind 0.0.0.0:$PORT`
5. Add environment variables in the Render dashboard:
   - `ADMIN_USERNAME`
   - `ADMIN_PASSWORD_HASH`
   - `SECRET_KEY`

> **Note:** Render's free tier has an ephemeral filesystem — the SQLite DB resets on redeploy. For persistent storage, mount a Render Disk (paid) or swap to a hosted Postgres with the SQLite schema migrated.

### Railway

1. Push to GitHub → New Project → Deploy from GitHub
2. Add the env vars under **Variables**
3. Railway auto-detects the `Procfile`

### Self-hosted (VPS / Ubuntu)

```bash
# Install nginx + certbot for HTTPS
sudo apt install nginx certbot python3-certbot-nginx

# Run gunicorn as a systemd service (see /etc/systemd/system/pkguard.service)
# Then proxy via nginx on port 80/443
```

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/api/scan` | No | Scan a `package.json`. Body: `{"packageJson": "<json string>"}` |
| `GET` | `/api/stats` | No | Returns DB stats (total threats, critical count, typosquat targets) |
| `GET` | `/api/tools` | No | List all tools in the security arsenal |
| `POST` | `/api/tools` | ✅ | Add a new tool. Fields: `type, cls, name, desc, url` |
| `DELETE` | `/api/tools/<id>` | ✅ | Remove a tool by ID |

### Scan request example

```bash
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"packageJson": "{\"dependencies\":{\"lodash\":\"4.17.15\",\"axios\":\"0.21.0\"}}"}'
```

### Scan response shape

```json
{
  "summary": {
    "total_packages": 2,
    "safe": 0,
    "flagged": 2,
    "by_severity": { "critical": 0, "high": 0, "medium": 2, "low": 0 },
    "risk_score": 16
  },
  "direct": [
    {
      "name": "lodash",
      "version": "4.17.15",
      "safe": false,
      "max_severity": "medium",
      "flags": [ { "type": "vulnerability", "severity": "medium", "title": "...", ... } ],
      "suggestion": {
        "name": "lodash",
        "version": "4.17.21",
        "reason": "Minimum patched version per OSV advisory",
        "install": "npm install lodash@4.17.21",
        "warning": false
      }
    }
  ],
  "indirect": [],
  "scanned_at": "2026-06-12T14:00:00+00:00"
}
```

---

## Suggestion Logic

For each flagged package, PkgGuard resolves a suggestion using this priority chain:

1. **Typosquat** → resolves the legitimate package name via fuzzy match against the targets list
2. **Not found** → fuzzy-matches the name against known legitimate packages
3. **Vulnerability / malware / backdoor / sabotage**:
   - OSV `fixed` version (exact minimum patched version from the advisory)
   - → fallback: npm `dist-tags.latest`
   - → if latest is also flagged in the DB: **warning** — "Latest is also compromised, remove this package"
   - → if already on latest: **warning** — "Await upstream patch or find an alternative"

---

## Admin Panel

Navigate to `/admin` in your browser. You will be prompted for HTTP Basic Auth credentials matching `ADMIN_USERNAME` and `ADMIN_PASSWORD_HASH` from your `.env`.

From the admin panel you can add and remove entries from the **Security Arsenal** tools directory shown on the homepage.

---

## Data Sources

| Source | What it checks |
|--------|----------------|
| PkgGuard DB | Known malware, backdoors, hijacked packages, typosquats |
| [OSV.dev](https://osv.dev) | Live CVE / GitHub Advisory data |
| [npm Registry](https://registry.npmjs.org) | Package age, maintainer count, publish velocity, latest version |

---

## License

MIT © [Aftersnow](https://aftersnow.xyz)
