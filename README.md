# SecureDocs - Security Assessment and Hardening of a File Upload App

Flask + SQLite + Bootstrap, run with Docker. The SAME code runs in two modes (`SECUREDOCS_MODE`):
**hardened** (default, port 5000) and **vulnerable** (lab only, port 5001, needs `--profile lab`).
Demo accounts (dummy): `alice / Alice@12345`, `bob / Bob@12345`.

## Verification status
- VERIFIED (15 automated tests pass, `python -m pytest -v`): both modes' behaviour in TESTING.md.
- NOT verified by the author: Docker build/run, Burp Suite/ZAP steps, screenshots, ZAP scan results. Run them and record real results.

## Fresh Windows setup
1. Install Docker Desktop (https://www.docker.com/products/docker-desktop), start it, wait for "Engine running". Install Burp Suite Community, OWASP ZAP, Python 3.12 (optional, for tests).
2. Extract the ZIP, then in PowerShell: `cd C:\path\to\securedocs`
3. `Copy-Item .env.example .env` and edit `SECRET_KEY` to a long random string.
4. Hardened only: `docker compose up -d --build`  -> http://localhost:5000
5. Add vulnerable lab: `docker compose --profile lab up -d --build`  -> http://localhost:5001
6. Status: `docker compose ps` | Logs: `docker compose logs -f hardened` | Health: `Invoke-RestMethod http://localhost:5000/health`
7. Stop: `docker compose --profile lab down` | Reset data too: `docker compose --profile lab down -v` | Rebuild after code edits: `docker compose --profile lab up -d --build`
8. Tests (optional): `py -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install -r requirements-dev.txt; python -m pytest -v`

## Isolation (why the vulnerable lab can't be exposed by accident)
- Starts only with `--profile lab`; the app also refuses to boot unless `LAB_ACK=I_AM_LOCAL_AND_ISOLATED` is set (compose sets it for the lab service only).
- Ports bind to `127.0.0.1` only. Never change this to `0.0.0.0` or port-forward it. Run on a personal laptop, not a shared/college network.
- Containers: non-root user, read-only filesystem, all capabilities dropped, no-new-privileges.

## Troubleshooting
- `docker` not found / engine not running -> start Docker Desktop. Port in use -> change the left port in docker-compose.yml.
- Page has no styling -> Bootstrap loads from a CDN; you need internet in the browser.
- Burp can't see localhost traffic -> use `http://localhost.:5000` or `http://127.0.0.1:5000` (trailing dot / IP) or use Burp's built-in browser.
