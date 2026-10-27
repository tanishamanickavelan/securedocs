# SecureDocs — Project Explanation & Comprehensive Viva Guide

**Project Title:** SecureDocs — Web Application Security Assessment and Remediation  
**Academic Requirement:** "Take any one website, understand the techniques, identify the security issues, and provide solutions to those problems."  
**Student Degree:** B.Tech Computer Science / Cybersecurity  
**Demonstration Target:** Local Hardened Application (`http://127.0.0.1:5000`)  

---

## 1. Project Objective

The primary objective of this project is to take a realistic web application—specifically a multi-user document management portal called **SecureDocs**—assess it systematically for common web vulnerabilities defined in the **OWASP Top 10** and the **OWASP Web Security Testing Guide (WSTG)**, demonstrate how attackers could exploit these flaws, and engineer verifiable, defense-in-depth code remediations.

SecureDocs implements a dual-mode architectural model:
1. **Vulnerable Mode (Lab):** Contains common security misconfigurations and coding oversights typical of beginner web applications (such as trusting client input, missing object-level access controls, and omitting defensive HTTP headers).
2. **Hardened Mode (Remediated):** Implements defensive controls including server-side validation, binary magic-byte checks, strict object-level authorization, anti-CSRF tokens, cryptographic hashing, and comprehensive HTTP security headers.

---

## 2. Technology Stack

- **Backend Framework:** Python 3.13, Flask 3.0.3 (WSGI architecture)
- **Database:** SQLite 3 (`data/securedocs.db`) with foreign key constraints and hashed credential storage
- **Password Security:** Scrypt / PBKDF2 with unique cryptographic salt via `werkzeug.security`
- **Frontend / UI:** Jinja2 server-rendered templates, Bootstrap 5.3.3 CSS loaded via CDN with Sub Resource Integrity (SRI)
- **Testing & Tooling:**
  - Automated Unit/Integration Testing: `pytest 8.3.3` (16 automated tests)
  - Security Scanning: `OWASP ZAP 2.17.0` (Dynamic Application Security Testing - DAST)
  - HTTP Verification: Python `urllib`, `curl`, and Chrome DevTools
  - Operating Environment: Windows 11 PowerShell

---

## 3. Application Architecture and Request Flow

SecureDocs operates on a three-tier architecture:

```
[Client / Browser / Attacker]
            │
            ▼
    [HTTP Request]
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│ Flask Web Application (Hardened Pipeline)                   │
│                                                             │
│ 1. @app.before_request (Global Security Interceptor)        │
│    - Checks HTTP method. If POST, extracts 'csrf_token'    │
│    - Compares using secrets.compare_digest()               │
│    - Aborts with HTTP 400 if missing or invalid             │
│                                                             │
│ 2. Route Dispatch & Authentication                          │
│    - @login_required decorator verifies session["user_id"]  │
│                                                             │
│ 3. Object-Level Access Control (Authorization / Anti-IDOR) │
│    - get_doc(doc_id):                                       │
│      SELECT * FROM documents WHERE id=? AND owner_id=?      │
│    - Aborts with HTTP 404 if user is not the owner          │
│                                                             │
│ 4. File Upload Security Pipeline (security.py)              │
│    - Size check: MAX_CONTENT_LENGTH (2 MB limit -> 413)     │
│    - Extension allowlist: txt, pdf, png, jpg, jpeg          │
│    - Content validation: Binary signature (magic bytes)     │
│    - Storage decoupling: uuid.uuid4().hex + '.' + ext       │
│    - Saved outside web root (/data/uploads)                 │
│                                                             │
│ 5. Safe Delivery / Download                                 │
│    - Content-Disposition: attachment                        │
│    - Previews restricted to safe types (png, jpg, txt)      │
│    - Sandboxed Content-Security-Policy on preview           │
│                                                             │
│ 6. @app.after_request (Header Injection Hook)               │
│    - Content-Security-Policy                                │
│    - X-Content-Type-Options: nosniff                        │
│    - X-Frame-Options: DENY                                  │
│    - Referrer-Policy: no-referrer                           │
│    - Cache-Control: no-store                                │
└─────────────────────────────────────────────────────────────┘
            │
            ▼
┌─────────────────────────────────────────────────────────────┐
│ Storage Layer (Data Separation)                             │
│ - Metadata: data/securedocs.db (SQLite)                     │
│ - Blobs: data/uploads/<uuid-hex>.<ext> (Not in web root)   │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Vulnerability Assessment Methodology

The security assessment followed the **OWASP Web Security Testing Guide (WSTG v4.2)**:

1. **Information Gathering:** Inspected HTTP response headers, server banners, cookie attributes, and CDN inclusions using DevTools, cURL, and OWASP ZAP passive scanning.
2. **Authentication & Session Testing:** Tested session creation, session cookie attributes (`HttpOnly`, `SameSite`, `Secure`), credential storage hashing, and session fixation defense.
3. **Authorization & Access Control Testing (WSTG-ATHZ-02):** Tested for Insecure Direct Object References (IDOR) by authenticating as user `bob` and requesting private documents owned by user `alice`.
4. **Input Validation & File Upload Testing (WSTG-BUSL-08 / WSTG-INVP-11):**
   - Attempted upload of disallowed extensions (`.exe`, `.html`, `.sh`).
   - Attempted MIME-type spoofing by changing client `Content-Type` header while supplying mismatched extensions.
   - Tested magic-byte validation by uploading plain text renamed to `fake.pdf`.
   - Tested upload size boundary limits with payloads exceeding 2 MB.
   - Tested directory traversal by submitting filenames containing `../`.
5. **Client-Side Security Testing:** Analyzed Cross-Site Request Forgery (CSRF) on state-changing POST endpoints and verified Sub Resource Integrity (SRI) on external scripts/stylesheets.
6. **Remediation & Regression Testing:** Implemented minimal, robust server-side controls and verified both positive and negative test cases using automated pytest suites and live verification scripts.

---

## 5. Important Vulnerabilities, Impact, and Solutions

### 1. Insecure Direct Object References (IDOR) — OWASP Top 10 A01:2021
- **What it is:** The application references database records directly by their primary key (`id=1`) without verifying whether the requesting user actually owns the record.
- **Impact:** Complete breach of data confidentiality. Any logged-in user could read, download, or delete every document in the system.
- **Solution:** Enforce authorization at the query level:
  `SELECT * FROM documents WHERE id=? AND owner_id=?`
  If no record matches, return HTTP 404 (Not Found) rather than 403 (Forbidden) so an attacker cannot even determine if the document ID exists.

### 2. Cross-Site Request Forgery (CSRF) — OWASP Top 10 A01:2021
- **What it is:** An attacker lures an authenticated user to a malicious webpage that secretly submits a form (e.g., POST `/delete/1`) using the victim's ambient browser cookies.
- **Impact:** Unauthorized state modification (e.g., unintended deletion of documents or unauthorized uploads).
- **Solution:** Implement the Synchronizer Token Pattern. A cryptographically random token (`secrets.token_hex(16)`) is stored in the user's session and rendered in forms. The server compares the submitted form token with the session token using `secrets.compare_digest` in a pre-request hook.

### 3. Dangerous File Uploads (Extension Bypass & MIME Spoofing)
- **What it is:** Attackers upload executable scripts or HTML files claiming to be legitimate documents.
- **Impact:** Stored Cross-Site Scripting (XSS), Remote Code Execution (RCE), or server compromise.
- **Solution:** Three-tier validation:
  1. Strict extension allowlist (`txt`, `pdf`, `png`, `jpg`).
  2. Binary header / magic-byte verification (e.g., checking for `%PDF-` on PDFs and PNG header bytes).
  3. Safe storage: Storing files with randomly generated UUID filenames in a directory outside the web root, and serving downloads strictly with `Content-Disposition: attachment`.

### 4. Path Traversal via Filename (`../`)
- **What it is:** An attacker submits a filename like `../../system.ini` in the upload multipart header.
- **Impact:** Overwriting arbitrary server files or placing files into executable directories.
- **Solution:** Never use the client-supplied filename for disk storage. Generate a server-controlled filename (`uuid.uuid4().hex + '.' + ext`) and sanitize the display name using `secure_filename()`.

### 5. Missing Defensive HTTP Headers
- **What it is:** Absence of browser instructions that restrict resource loading and iframe embedding.
- **Impact:** Clickjacking, MIME-type sniffing attacks, and cross-site data leaks.
- **Solution:** Emit defense-in-depth headers on every response:
  - `Content-Security-Policy`: Restricts script and resource execution.
  - `X-Content-Type-Options: nosniff`: Prevents browsers from guessing MIME types.
  - `X-Frame-Options: DENY`: Blocks framing and clickjacking.
  - `Cache-Control: no-store`: Prevents shared/browser caches from storing sensitive documents.

---

## 6. OWASP ZAP Assessment & Findings Analysis

During dynamic testing with OWASP ZAP 2.17.0, the following alerts were analyzed:

1. **Sub Resource Integrity (SRI) Attribute Missing (Medium):**
   - *Investigation:* Found that the CDN Bootstrap link initially lacked an `integrity` hash.
   - *Fix:* Added `integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"` and `crossorigin="anonymous"`.
   - *ZAP Behavior:* ZAP's UI retained historical alerts from an earlier crawl. Retesting a fresh proxied request confirmed zero new SRI alerts.
2. **Server Leaks Version Information via "Server" Header (Low):**
   - *Investigation:* Werkzeug dev server emits `Server: Werkzeug/3.0.4 Python/3.13.7`.
   - *Finding:* Application response hooks (`@app.after_request`) cannot strip socket-level headers added by the WSGI HTTP server layer.
   - *Remediation:* Requires a production reverse proxy (e.g., Nginx `server_tokens off;`).
3. **Session Management Response Identified (Informational):**
   - *Analysis:* ZAP recognizes the `Set-Cookie: session=...` header. Verified that `HttpOnly` and `SameSite=Lax` flags are present and active.
4. **User Controllable HTML Element Attribute (Informational):**
   - *Analysis:* ZAP observed that the hidden form field `csrf_token` contains user-session data. Jinja2 automatically escapes attribute values, and the token is an alphanumeric hex string; this is a false positive.

---

## 7. Limitations and Future Work

1. **Malware / Antivirus Scanning:** Magic-byte validation checks file structure, but does not detect malicious macro payloads inside valid PDFs or embedded image exploits. Production systems should integrate an antivirus scanner (e.g., ClamAV).
2. **Rate Limiting & Brute Force Defense:** Currently, the login endpoint does not enforce rate limiting (e.g., via Flask-Limiter or Redis). Repeated failed login attempts should trigger exponential backoff or temporary account lockout.
3. **HTTPS / TLS Deployment:** The local development server runs over HTTP (`http://127.0.0.1:5000`). In production, TLS must be terminated at a reverse proxy, enabling `Strict-Transport-Security` (HSTS) and `SESSION_COOKIE_SECURE = True`.
4. **Database Scalability:** SQLite is suitable for single-node development, but production enterprise systems require a multi-user transactional database (PostgreSQL) with connection pooling and encrypted tablespaces.
