# SecureDocs — Engineering & Verification Work Log

---

### Session Record
- **Date:** October 27, 2026
- **Assessor / Engineer:** Tanisha Manickavelan & Security Coding Assistant
- **Scope:** Local SecureDocs repository at `D:\Downloads\securedocs\securedocs`
- **Application Target:** `http://127.0.0.1:5000` (Flask Hardened Mode)
- **Active Tools:** Windows PowerShell, Python 3.13.7, Werkzeug 3.0.4, SQLite 3, OWASP ZAP 2.17.0

---

### 1. Initial Inspection & Environment Audit
- **Project Structure:** Discovered project located at `D:\Downloads\securedocs\securedocs` (origin: `https://github.com/tanishamanickavelan/securedocs.git`).
- **Git Status:** Clean working tree on `main` branch (commit `e098f51 Update SecureDocs security fixes`).
- **Database Safety Check:** Read-only inspection of `data/securedocs.db` conducted using `sqlite3` Python URI mode `mode=ro`. Confirmed existing tables (`users`, `documents`) and demo accounts (`alice`, `bob`, `Tanisha`, `ZAP`) are intact. Zero modifications or migrations executed against production database.
- **Running Server:** Found process ID 24744 (`python.exe`) already running on `127.0.0.1:5000`. Verified running command: `D:\Downloads\securedocs\securedocs\.venv\Scripts\python.exe -m flask --app app run --port 5000`. Server left running undisturbed.
- **OWASP ZAP Process:** Discovered OWASP ZAP 2.17.0 already running in background (PID 4880, `javaw.exe`) on port 8080 with API key `dgi35paf1gpvimhp369402pk0d`.

---

### 2. Problems Discovered & Solved

#### Problem 1: Drive C: Zero Free Disk Space & Pytest Crash
- **Observation:** Running `py -m pytest -v` crashed during test 6 with `OSError: [Errno 28] No space left on device` at `tempfile.py:500`.
- **Root Cause:** Drive `C:` had exactly 0.00 GB free disk space. Python's default temp directory and pytest's tempfile spooler failed when creating 3 MB test upload buffers in `AppData\Local\Temp`.
- **Fix:**
  1. Created isolated directory `D:\temp`.
  2. Created `pytest.ini` in the project root with `addopts = --basetemp=D:/temp/pytest`.
  3. Set `$env:TEMP = "D:\temp"; $env:TMP = "D:\temp"` in PowerShell sessions.
- **Result:** Pytest suite runs 100% cleanly without touching drive C:.

#### Problem 2: Malformed Bootstrap Link Tag & SRI False Positive
- **Observation:** `app/templates/base.html` contained an unclosed stray `<link ` tag right before the Bootstrap CSS link:
  ```html
  <link 

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
  ```
  Additionally, OWASP ZAP's UI continued to report "Sub Resource Integrity Attribute Missing" even after the integrity attribute was added.
- **Root Cause:**
  1. Broken HTML syntax artifact caused by an incomplete previous edit.
  2. In OWASP ZAP, alerts in the Alerts tab are tied to the historical HTTP message where they were initially captured. ZAP messages 9, 36, 46, 49, 50, 54, 57, and 58 were recorded during an earlier crawl before the integrity tag was applied.
- **Fix:**
  1. Cleaned `app/templates/base.html` and `base.html` to eliminate the stray `<link ` line.
  2. Verified official SRI hash against `https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css` (computed sha384 matched: `sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH`).
  3. Added automated test `test_h_sri_attribute_present` in `tests/test_app.py`.
  4. Proxied a new request through ZAP: verified that ZAP generated zero SRI alerts on the fresh message.

#### Problem 3: Server Header Version Disclosure
- **Observation:** `curl.exe -i http://127.0.0.1:5000/health` showed `Server: Werkzeug/3.0.4 Python/3.13.7` despite `resp.headers.pop("Server", None)` existing in `@app.after_request`.
- **Root Cause:** Flask's `@app.after_request` operates inside the WSGI application scope. Werkzeug's `WSGIRequestHandler` (derived from `http.server.BaseHTTPRequestHandler`) re-injects the `Server` header at the raw socket transport level during HTTP response line transmission.
- **Remediation Strategy:** Documented the architectural boundary: Application code cannot suppress socket-level WSGI headers. In production, this is remediated at the reverse proxy layer (e.g., Nginx `server_tokens off;` and `proxy_hide_header Server;`).

---

### 3. Tests & Verifications Executed

1. **Automated Live Security Verification Suite (`demo_preparation/verify_live.py`):**
   - Executed against `http://127.0.0.1:5000`.
   - Results: **12 / 12 PASS (100%)**:
     - Hardened Mode Check -> PASS
     - Security Headers Verification (CSP, nosniff, DENY, no-referrer, no-store) -> PASS
     - Session Cookie Flags (HttpOnly=True, SameSite=Lax) -> PASS
     - Alice Authentication & Session Creation -> PASS
     - Authorized Download with Content-Disposition: attachment -> PASS
     - IDOR Download Prevention (Bob accessing Alice doc 1) -> HTTP 404 PASS
     - IDOR Preview Prevention -> HTTP 404 PASS
     - IDOR Delete Prevention -> HTTP 404 PASS
     - CSRF Protection (POST without token) -> HTTP 400 PASS
     - Disallowed File Extension (`malicious.exe`) -> Flash Error PASS
     - Magic Bytes Mismatch (`fake.pdf`) -> Flash Error PASS
     - Upload Size Restriction (>2 MB) -> HTTP 413 PASS

2. **Pytest Regression Suite:**
   - Command: `py -m pytest -v` (with `pytest.ini` basetemp).
   - Results: **16 / 16 PASS in 5.13s**.

3. **OWASP ZAP Live Query & Report Export:**
   - Queried active ZAP session via REST API.
   - Generated genuine scan report: `demo_preparation/evidence/zap_report.html` (84 KB) and `demo_preparation/evidence/zap_report.json` (38 KB).

---

### 4. Files Created / Modified

- **Modified:**
  - `app/templates/base.html` — Removed malformed `<link ` line; verified SRI integrity attribute.
  - `base.html` — Synced root template with `integrity` and `crossorigin` attributes.
  - `tests/test_app.py` — Added `test_h_sri_attribute_present` test case.
- **Created:**
  - `pytest.ini` — Configured pytest to use `D:/temp/pytest` basetemp.
  - `demo_preparation/verify_live.py` — Standalone automated live endpoint verification script.
  - `demo_preparation/PROJECT_STATUS.md` — Project tracking checklist.
  - `demo_preparation/WORK_LOG.md` — Detailed session work log.
  - `demo_preparation/VULNERABILITY_REPORT.md` — Comprehensive assessment report with before/after table.
  - `demo_preparation/TEST_RESULTS.md` — Test evidence and results matrix.
  - `demo_preparation/PROJECT_EXPLANATION.md` — Complete B.Tech level technical project explanation.
  - `demo_preparation/DEMO_SCRIPT.md` — Natural 5–7 minute oral presentation script.
  - `demo_preparation/DEMO_STEPS.md` — Step-by-step browser and PowerShell demonstration walkthrough.
  - `demo_preparation/VIVA_QUESTIONS.md` — 18 examiner questions and answers.
  - `demo_preparation/LIMITATIONS_AND_FUTURE_WORK.md` — Honest project limitations and future enhancements.
  - `demo_preparation/evidence/README.md` — Evidence catalog and artifact index.
  - `demo_preparation/evidence/*` — Genuine raw test outputs, curl headers, and ZAP reports.

---

### 5. Next Recommended Action
- Practice the 5–7 minute demonstration script following the exact sequence in `demo_preparation/DEMO_STEPS.md`.
- Read through `demo_preparation/VIVA_QUESTIONS.md` to prepare for examiner queries.
