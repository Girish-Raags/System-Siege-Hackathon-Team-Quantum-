# WebGuard

**AI-assisted website defacement detection & vulnerability monitoring platform.**

WebGuard continuously watches web assets an organization owns, detects unauthorized
content changes (defacement), flags passive security-posture issues (missing
security headers, expiring TLS certs, accidentally exposed sensitive paths), and
uses Claude (with a deterministic rule-based fallback) to score risk and suggest
remediation — all behind role-based access control with a full audit trail.

> Domain: **Cybersecurity / Web Application Security & Monitoring**
Website: https://system-siege-hackathon-team-quantum-1.onrender.com/
---

## What it does

- **Continuous monitoring** — a background scheduler polls each registered asset
  on its own interval (default every 5 minutes, configurable per asset).
- **Defacement detection** — every scan is compared against a trusted baseline
  using a text-similarity change score (0–100). Crossing a threshold raises an
  anomaly and generates a unified diff excerpt for the alert.
- **Passive vulnerability checks** — missing security headers
  (CSP, HSTS, X-Frame-Options, etc.), disclosed server banners, TLS certificate
  expiry, and accidentally public sensitive paths (`.env`, `.git/config`, etc.)
  on your own asset.
- **AI-driven risk intelligence** — when `ANTHROPIC_API_KEY` is set, Claude reads
  the diff + findings and returns a risk score, plain-English summary, and
  prioritized remediation steps. Without a key, a transparent rule-based
  scorer does the same job so the platform works out of the box.
- **Alerting & triage** — alerts carry severity (critical/high/medium/low) and a
  status workflow (open → acknowledged → resolved / false positive).
- **RBAC** — `admin` (full control), `analyst` (manage assets, run scans, triage
  alerts), `viewer` (read-only dashboards).
- **Audit trail** — every login, asset change, scan, and alert-status update is
  logged with actor, target, and timestamp.
- **Centralized dashboard** — single-page UI showing all protected assets, a
  "pulse" history of recent change scores per asset, alert feed, and audit log.

## Architecture

```
webguard/
├── backend/
│   ├── app/
│   │   ├── main.py            # FastAPI app, startup bootstrap, static hosting
│   │   ├── config.py          # env-driven settings
│   │   ├── database.py        # SQLAlchemy engine/session
│   │   ├── models.py          # User, Asset, Scan, Alert, AuditLog
│   │   ├── schemas.py         # Pydantic request/response models
│   │   ├── core/
│   │   │   ├── security.py    # JWT auth, password hashing, RBAC dependency
│   │   │   └── audit.py       # audit log writer
│   │   ├── monitor/
│   │   │   ├── fetcher.py     # HTTP fetch, headers/TLS/exposed-path checks
│   │   │   ├── differ.py      # change-score + diff excerpt
│   │   │   ├── engine.py      # orchestrates a full scan + alert creation
│   │   │   └── scheduler.py   # APScheduler background jobs, one per asset
│   │   ├── ai/
│   │   │   └── analyzer.py    # Claude-based risk analysis + rule-based fallback
│   │   └── routers/           # auth, users, assets, scans, alerts, audit, dashboard
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   └── index.html             # single-page dashboard (vanilla HTML/CSS/JS)
├── docker-compose.yml
├── .env.example
└── README.md
```

**Stack:** FastAPI + SQLAlchemy (SQLite by default, swappable to Postgres) +
APScheduler for background jobs + a dependency-free HTML/JS frontend served
directly by FastAPI (no build step, no Node required).

## Why these design choices

- **SQLite by default** so anyone can clone and run this in under a minute; set
  `DATABASE_URL` to a Postgres connection string for production.
- **No frontend build step** — the dashboard is a single static HTML file that
  talks to the API over `fetch()`. This keeps the deployable surface to "one
  Python process," which matters for a hackathon judge trying to run it fast.
- **AI is additive, not a dependency** — every core feature (detection, alerting,
  RBAC, audit) works with zero external API keys. Claude only makes the
  *risk narrative* better; it never gates functionality.
- **Passive-only scanning** — all checks are ordinary HTTP GET/HEAD requests and
  a TLS handshake against assets you already own. There's no exploitation,
  brute-forcing, or third-party scanning.

---

## Run it locally (fastest path)

Requires Python 3.11+.

```bash
git clone <your-fork-url> webguard
cd webguard/backend
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example ../.env   # then edit values as needed
uvicorn app.main:app --reload --port 8000
```

Open **http://localhost:8000** — a bootstrap admin account is created
automatically on first startup:

- Email: `admin@webguard.local` (override with `BOOTSTRAP_ADMIN_EMAIL`)
- Password: `ChangeMe123!` (override with `BOOTSTRAP_ADMIN_PASSWORD`)

**Change the bootstrap password before exposing this publicly.**

### Enable AI-driven risk scoring (optional)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Without this, WebGuard automatically falls back to deterministic rule-based
scoring — nothing breaks, alerts just say `"ai_source": "rule-based"` instead
of `"anthropic"`.

## Run it with Docker (recommended for deployment)

```bash
cp .env.example .env   # edit SECRET_KEY, admin password, and (optionally) ANTHROPIC_API_KEY
docker compose up --build
```

The app is now on **http://localhost:8000**, with data persisted in the
`webguard_data` Docker volume.

## Deploy it live in ~5 minutes

Any host that runs a Dockerfile works. Two free options:

### Option A — Render
1. Push this repo to GitHub (see below).
2. In Render: **New → Web Service → connect this repo**.
3. Environment: **Docker**. Render auto-detects `backend/Dockerfile`; set
   **Dockerfile Path** to `backend/Dockerfile` and **Docker Build Context** to
   the repo root (`.`).
4. Add environment variables from `.env.example` (at minimum `SECRET_KEY`,
   `BOOTSTRAP_ADMIN_EMAIL`, `BOOTSTRAP_ADMIN_PASSWORD`; add `ANTHROPIC_API_KEY`
   if you want AI-driven risk scoring).
5. Add a **Disk** mounted at `/data` if you want the SQLite DB to survive
   redeploys (or switch `DATABASE_URL` to a Render Postgres instance).
6. Deploy. Render gives you a public `https://<app>.onrender.com` URL.

### Option B — Railway / Fly.io
Both auto-detect the Dockerfile the same way. On Railway: **New Project → Deploy
from GitHub repo**, set the root Dockerfile path to `backend/Dockerfile` with
build context `.`, add the same environment variables, and deploy. On Fly.io,
run `fly launch` from the repo root, point it at `backend/Dockerfile`, then
`fly deploy`.

### Option C — any VM (systemd)
```bash
git clone <repo> && cd webguard
docker compose up -d --build
```
Put a reverse proxy (Caddy/Nginx) in front for TLS termination on your own
domain.

## Pushing this to your own GitHub

```bash
cd webguard
git init                       # if not already a repo
git add -A
git commit -m "WebGuard: website defacement detection & vulnerability monitoring platform"
git branch -M main
git remote add origin https://github.com/<you>/webguard.git
git push -u origin main
```

## Using the platform

1. Sign in with the bootstrap admin account.
2. **Assets tab** → add a website by name + URL. The first scan runs
   immediately and becomes the trusted baseline; recurring scans run on the
   interval you set (minimum 60 seconds).
3. Watch the **pulse strip** on each asset card — it's the last 20 change
   scores; a red bar means that scan was flagged anomalous.
4. **Scan now** triggers an immediate check; **Accept as baseline** tells
   WebGuard the current live content is legitimate (use this after an
   intentional site update, so it stops alerting on it).
5. **Alerts tab** shows open/ack'd/resolved/false-positive alerts with the
   AI (or rule-based) summary and remediation steps; change status inline.
6. **Audit trail tab** (admin only) shows every action taken on the platform.

### API surface

Interactive API docs are auto-generated by FastAPI at **`/docs`** once the
server is running (e.g. `http://localhost:8000/docs`) — useful for scripting
against WebGuard or building your own integrations.

### Managing users & roles

Only `admin` can create users or change roles:

```bash
curl -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer <admin_token>" \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@yourorg.com","password":"StrongPassw0rd!","role":"analyst"}'
```

## Configuration reference

See `.env.example` for the full list. Key ones:

| Variable | Purpose | Default |
|---|---|---|
| `DATABASE_URL` | SQLAlchemy connection string | `sqlite:///./webguard.db` |
| `SECRET_KEY` | JWT signing key — **set a real random value in production** | auto-generated (unsafe for prod) |
| `ANOMALY_THRESHOLD` | Change score (0–100) above which a scan is flagged | `18.0` |
| `ANTHROPIC_API_KEY` | Enables Claude-based risk analysis; omit to use rule-based scoring | unset |
| `BOOTSTRAP_ADMIN_EMAIL` / `BOOTSTRAP_ADMIN_PASSWORD` | First admin account, created once | see `.env.example` |

## Security notes

- Change `SECRET_KEY` and the bootstrap admin password before any public
  deployment.
- All monitoring checks are passive (GET/HEAD requests, TLS handshake) against
  assets you have the right to monitor — do not point this at sites you don't
  own or operate.
- Passwords are hashed with bcrypt; tokens are short-lived JWTs (default 8h,
  configurable).

## License

MIT — do whatever you like, no warranty provided.
