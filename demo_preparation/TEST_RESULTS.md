# SecureDocs — Verified Test Results Matrix

**Test Date:** October 27, 2026  
**Target:** Local Hardened Application (`http://127.0.0.1:5000`)  
**Environment:** Python 3.13.7, Flask 3.0.3, SQLite 3, Windows PowerShell  
**Isolation Notice:** Tests run against the running hardened instance using isolated session states; automated unit tests run in temporary directory via `pytest.ini`. The real production database (`data/securedocs.db`) remained completely uncorrupted.

---

## 1. Live Integration Test Results (`demo_preparation/verify_live.py`)

| # | Test | Expected result | Actual result | Status | Evidence |
|---|---|---|---|:---:|---|
| 1 | **Hardened Mode Status** | HTTP 200 with JSON response `{"mode":"hardened","status":"ok"}` | HTTP 200: `{"mode":"hardened","status":"ok"}` | **PASS** | `verify_live_output.txt`: `{"mode":"hardened","status":"ok"}` returned on `/health`. |
| 2 | **Security Headers (CSP, XCTO, XFO, RP, CC)** | CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` | All 5 defensive headers present in HTTP response headers | **PASS** | `http_headers_hardened.txt`: Verified on `/login` and `/health` responses. |
| 3 | **Session Cookie Security Attributes** | `HttpOnly=True` and `SameSite=Lax` present on `session` cookie | `Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax` | **PASS** | Captured header: `Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax`. |
| 4 | **Authorized Document Download** | Alice requesting her own document (`/download/1`) receives HTTP 200 with attachment header | HTTP 200 with `Content-Disposition: attachment; filename=alice-notes.txt` | **PASS** | Download succeeds with forced attachment header preventing browser script execution. |
| 5 | **IDOR Prevention on Download** | Bob requesting Alice's document (`/download/1`) receives HTTP 404 | HTTP 404 NOT FOUND | **PASS** | `verify_live_output.txt`: Query enforces `WHERE id=? AND owner_id=?`, concealing document existence. |
| 6 | **IDOR Prevention on Preview** | Bob requesting inline preview of Alice's document (`/preview/1`) receives HTTP 404 | HTTP 404 NOT FOUND | **PASS** | `verify_live_output.txt`: `get_doc(1)` raises 404 abort before preview handler runs. |
| 7 | **IDOR Prevention on Delete** | Bob requesting deletion of Alice's document (POST `/delete/1`) receives HTTP 404 | HTTP 404 NOT FOUND | **PASS** | `verify_live_output.txt`: `get_doc(1)` raises 404 abort; document remains in database. |
| 8 | **CSRF Protection on Sensitive Action** | POST request to `/delete/1` without valid `csrf_token` receives HTTP 400 | HTTP 400 BAD REQUEST ("CSRF token missing or invalid.") | **PASS** | `before_request` hook intercepts POST before route execution and aborts with 400. |
| 9 | **Disallowed File Extension Rejection** | Upload of executable (`malicious.exe`) is rejected | Application rejects upload; flashes "This file type is not allowed. Allowed: txt, pdf, png, jpg." | **PASS** | Handled by `security.py::validate_upload()` extension whitelist. |
| 10 | **Magic Bytes / Content Mismatch Rejection** | Upload of renamed plain text file (`fake.pdf`) is rejected | Application rejects upload; flashes "File content does not match its extension." | **PASS** | Handled by `security.py::validate_upload()` checking `data.startswith(SIGNATURES['pdf'])` (`%PDF-`). |
| 11 | **Upload File Size Limitation** | Upload of file exceeding 2 MB (3 MB payload) receives HTTP 413 | HTTP 413 REQUEST ENTITY TOO LARGE | **PASS** | Intercepted by Flask/Werkzeug `MAX_CONTENT_LENGTH = 2 * 1024 * 1024`. |
| 12 | **Path Traversal Filename Sanitization** | Upload with filename `../../escape.txt` cannot traverse out of uploads directory | File stored on disk with random 32-character UUID (`<uuid4>.txt`) | **PASS** | Server generates internal storage name using `uuid.uuid4().hex + '.' + ext`. |

---

## 2. Automated Regression Test Suite (`tests/test_app.py`)

Run command: `py -m pytest -v` (with `pytest.ini` basetemp).

| # | Test Function Name | Test Description | Expected Result | Actual Result | Status |
|---|---|---|---|---|:---:|
| 1 | `test_health_and_headers` | Verifies `/health` returns hardened mode and core headers | Mode = hardened, headers present | PASSED | **PASS** |
| 2 | `test_h_rejects_disallowed_extension` | Upload of `page.html` in hardened mode | Rejection message "not allowed" | PASSED | **PASS** |
| 3 | `test_h_rejects_mime_spoof` | Upload of `fake.png` with text content | Rejection message "does not match" | PASSED | **PASS** |
| 4 | `test_h_accepts_valid_and_randomizes_name` | Upload valid PNG image | Saved with 32-hex UUID filename | PASSED | **PASS** |
| 5 | `test_h_traversal_name_is_neutralised` | Traversal path `../../escape.txt` | No file written to parent dirs | PASSED | **PASS** |
| 6 | `test_h_oversize_rejected` | Upload 3 MB file in hardened mode | Returns HTTP 413 | PASSED | **PASS** |
| 7 | `test_h_idor_blocked` | Bob accesses doc 1 (download, preview, delete) | All three return HTTP 404 | PASSED | **PASS** |
| 8 | `test_h_csrf_required` | POST `/delete/1` with empty POST body | Returns HTTP 400 | PASSED | **PASS** |
| 9 | `test_h_password_is_hashed` | Password column in SQLite users table | Uses modern scrypt or pbkdf2 hash | PASSED | **PASS** |
| 10 | `test_h_download_is_attachment` | Download route response header | `Content-Disposition: attachment` | PASSED | **PASS** |
| 11 | `test_h_sri_attribute_present` | Base template contains SRI & crossorigin | `integrity="sha384-"` present | PASSED | **PASS** |
| 12 | `test_v_refuses_without_ack` | Vulnerable lab mode without confirmation ack | Raises `RuntimeError` | PASSED | **PASS** |
| 13 | `test_v_accepts_html_with_spoofed_mime` | Vulnerable lab accepts `.html` file | Preview served as `text/html` | PASSED | **PASS** |
| 14 | `test_v_path_traversal_writes_outside_upload_dir` | Vulnerable lab allows filename path traversal | File written to parent `/data` | PASSED | **PASS** |
| 15 | `test_v_idor_download_and_delete` | Vulnerable lab allows cross-user document access | Bob downloads doc 1 with HTTP 200 | PASSED | **PASS** |
| 16 | `test_v_no_security_headers` | Vulnerable lab headers check | CSP and nosniff absent | PASSED | **PASS** |

**Summary:** 16 passed, 0 failed, 0 skipped in 5.13s.
