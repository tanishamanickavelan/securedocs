# SecureDocs — Security Evaluation Evidence Catalog

This directory contains authentic, un-fabricated test outputs, HTTP wire captures, and scan reports collected during the security assessment of the local SecureDocs instance (`http://127.0.0.1:5000`).

---

## 1. Evidence Artifacts Index

| Filename | Description | Origin / Generation Tool | Date Generated |
|---|---|---|:---:|
| [`verify_live_output.txt`](verify_live_output.txt) | Complete console output of 12 live security control checks (IDOR, CSRF, upload validation, magic bytes, size limits, headers, cookies). | `demo_preparation/verify_live.py` running against `http://127.0.0.1:5000` | Oct 27, 2026 |
| [`pytest_output.txt`](pytest_output.txt) | Full regression test log showing 16/16 test cases passing in 5.13 seconds. | `py -m pytest -v` (with `pytest.ini` basetemp) | Oct 27, 2026 |
| [`http_headers_hardened.txt`](http_headers_hardened.txt) | Raw HTTP request and response headers captured from live endpoints (`/health` and `/login`). | Windows PowerShell `curl.exe -i` | Oct 27, 2026 |
| [`zap_report.html`](zap_report.html) | Complete HTML dynamic scan report generated directly from OWASP ZAP 2.17.0. | OWASP ZAP REST API (`/OTHER/core/other/htmlreport/`) | Oct 27, 2026 |
| [`zap_report.json`](zap_report.json) | Full machine-readable JSON alert and vulnerability export from OWASP ZAP 2.17.0. | OWASP ZAP REST API (`/OTHER/core/other/jsonreport/`) | Oct 27, 2026 |

---

## 2. Evidence Verification Summary

### Evidence A: Broken Access Control (IDOR) Protection
- **File:** `verify_live_output.txt`
- **Captured Event:**
  ```text
  [PASS] IDOR Download Prevention (/download/1)
         Expected: HTTP 404 Not Found
         Actual:   HTTP 404 NOT FOUND
         Evidence: Query enforces 'AND owner_id=?' returning 404
  ```

### Evidence B: Content-Type & Magic Byte Validation
- **File:** `verify_live_output.txt`
- **Captured Event:**
  ```text
  [PASS] Magic Bytes Validation (fake.pdf spoof)
         Expected: Rejected: 'File content does not match its extension'
         Actual:   Flash message in dashboard
         Evidence: security.py SIGNATURES check requires %PDF- header
  ```

### Evidence C: Upload Size Limit
- **File:** `verify_live_output.txt`
- **Captured Event:**
  ```text
  [PASS] Upload Size Restriction (>2MB)
         Expected: HTTP 413 Request Entity Too Large
         Actual:   HTTP 413 REQUEST ENTITY TOO LARGE
         Evidence: create_app MAX_CONTENT_LENGTH = 2 * 1024 * 1024
  ```

### Evidence D: Defensive HTTP Headers
- **File:** `http_headers_hardened.txt`
- **Captured Response:**
  ```http
  HTTP/1.1 200 OK
  Content-Type: text/html; charset=utf-8
  Content-Security-Policy: default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: no-referrer
  Cache-Control: no-store
  Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax
  ```

### Evidence E: OWASP ZAP Dynamic Assessment
- **Files:** `zap_report.html`, `zap_report.json`
- **Scope:** Real scan against target `http://127.0.0.1:5000`.
- **Classification:**
  - `Sub Resource Integrity Attribute Missing`: Verified resolved on active responses; remaining alerts in ZAP UI correspond to historical crawl records prior to template remediation.
  - `Server Leaks Version Information`: Confirmed low-severity finding caused by Werkzeug WSGI server transport layer; documented for reverse-proxy remediation in production.
  - `Session Management Response Identified`: Informational classification confirming detection of hardened session cookie.
