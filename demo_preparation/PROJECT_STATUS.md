# SecureDocs — Project Status & Tracking Matrix

**Project:** SecureDocs — Web Application Security Assessment and Remediation  
**Academic Requirement:** "Take any one website, understand the techniques, identify the security issues, and provide solutions to those problems."  
**Target Environment:** Local Flask Application (`http://127.0.0.1:5000`) on Windows PowerShell  
**Current Date:** October 27, 2026  
**Demonstration Date:** October 28, 2026 (Tomorrow)

---

## 1. Overall Status Summary

| Area | Status | Verification Summary |
|---|---|---|
| Technical Environment & Startup | **DONE** | Flask app running locally on port 5000 in hardened mode (`.venv` Python 3.13.7). |
| Database & Data Integrity | **DONE** | SQLite DB (`data/securedocs.db`) preserved intact with existing demo accounts and documents. |
| Core Security Controls | **DONE** | 12/12 live security tests verified against `http://127.0.0.1:5000` (100% pass rate). |
| Automated Unit/Integration Tests | **DONE** | 16/16 pytest test cases passing in `tests/test_app.py` via `pytest.ini`. |
| Bootstrap SRI Validation | **DONE** | Validated official hash `sha384-QWTKZyjp...`; fixed syntax artifact in `app/templates/base.html`; re-verified in ZAP. |
| Server Header Analysis | **DONE** | Root cause analyzed (Werkzeug WSGI server layer); mitigation path documented (reverse proxy). |
| OWASP ZAP Assessment & Evidence | **DONE** | Genuine ZAP HTML and JSON reports extracted; alerts analyzed and classified. |
| Demonstration Materials | **DONE** | 5–7 min demo script, step-by-step PowerShell/browser instructions, and 18 viva Q&As prepared. |

---

## 2. Detailed Task Checklist

| # | Task / Control | Status | Evidence Supporting Status | Next Action Required |
|---|---|:---:|---|---|
| 1 | **Environment Discovery & Startup** | **DONE** | Active process listening on `127.0.0.1:5000` verified via PowerShell `Get-NetTCPConnection`. `/health` responds with `{"mode":"hardened","status":"ok"}`. | Keep running in user's terminal during live viva demo. |
| 2 | **Database Protection** | **DONE** | `data/securedocs.db` queried read-only: Users (`alice`, `bob`, `Tanisha`, `ZAP`) and documents preserved. No schema resets or destructive actions taken. | Maintain strict read-only / non-destructive testing policy. |
| 3 | **Broken Object-Level Auth (IDOR)** | **DONE** | Bob requesting Alice's `/download/1`, `/preview/1`, and `/delete/1` returns HTTP 404. Live script `verify_live.py` and pytest test passed. | Demonstrate Bob's 404 in browser during demo step 1. |
| 4 | **Cross-Site Request Forgery (CSRF)** | **DONE** | POST `/delete/1` without CSRF token returns HTTP 400. Injected CSRF token validated with `secrets.compare_digest`. | Demonstrate in live test script / cURL. |
| 5 | **Upload File Size Limitation** | **DONE** | 3 MB file upload rejected with HTTP 413 (Payload Too Large). Controlled by `MAX_CONTENT_LENGTH = 2 * 1024 * 1024` in `create_app`. | Demonstrate via PowerShell cURL / automated test. |
| 6 | **Disallowed Extension Validation** | **DONE** | Upload of `malicious.exe` rejected with flash message `"This file type is not allowed"`. Allowed list: txt, pdf, png, jpg, jpeg. | Demonstrate upload attempt on web UI. |
| 7 | **File Content / Signature Mismatch** | **DONE** | Renamed `fake.pdf` (text data lacking `%PDF-` magic bytes) rejected with flash message `"File content does not match its extension"`. | Demonstrate upload of `fake.pdf` on web UI. |
| 8 | **Path Traversal Prevention** | **DONE** | Files stored using `uuid.uuid4().hex + '.' + ext` in dedicated upload folder outside web root. `test_h_traversal_name_is_neutralised` passed. | Highlight random UUID storage in code walkthrough. |
| 9 | **HTTP Security Headers** | **DONE** | CSP, X-Content-Type-Options: `nosniff`, X-Frame-Options: `DENY`, Referrer-Policy: `no-referrer`, Cache-Control: `no-store` confirmed in HTTP response. | Show response headers in DevTools / cURL. |
| 10 | **Session Cookie Flags** | **DONE** | Session cookie has `HttpOnly=True` and `SameSite=Lax`. `Secure` flag configurable via `COOKIE_SECURE` for HTTPS. | Show Application -> Cookies tab in browser. |
| 11 | **Bootstrap SRI Fix & Verification** | **DONE** | Fixed stray `<link ` in `app/templates/base.html`. Verified `sha384-QWTKZyjp...` matches CDN stylesheet. Verified zero alerts on fresh proxied requests in ZAP. | Explain in viva why ZAP showed older historical message. |
| 12 | **Server Header Leak Investigation** | **DONE** | Werkzeug server injects `Server: Werkzeug/3.0.4 Python/3.13.7` at WSGI socket level. Explain why reverse-proxy (Nginx) is the standard mitigation. | Include explanation in Viva Q&A and Vulnerability Report. |
| 13 | **OWASP ZAP Report Extraction** | **DONE** | Real scan report saved to `demo_preparation/evidence/zap_report.html` and `zap_report.json` via live ZAP API. | Keep files available for external examiner review. |
| 14 | **Regression Testing** | **DONE** | Added `test_h_sri_attribute_present` to pytest suite. Configured `pytest.ini` with basetemp on `D:\temp` to prevent C: drive out-of-space crash. 16/16 tests pass. | Run `py -m pytest -v` as final demonstration proof. |
| 15 | **Demo & Viva Deliverables** | **DONE** | All 10 deliverables completed in simple, confident academic English. | Rehearse 5-minute demo script before presentation. |

---

## 3. Environment & Storage Notice

> [!NOTE]
> During verification, it was detected that the machine's primary drive `C:` has 0.00 GB free disk space. To prevent standard Python `tempfile` crashes (`OSError: [Errno 28] No space left on device`), `pytest.ini` was created with `addopts = --basetemp=D:/temp/pytest`. All commands and scripts are explicitly configured to use `D:\temp`.
