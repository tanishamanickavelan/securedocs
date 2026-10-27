# SecureDocs — Limitations and Future Work

**Project:** SecureDocs — Web Application Security Assessment and Remediation  
**Scope:** Academic Security Evaluation and Defense-in-Depth Hardening  

---

## 1. Honest Technical Limitations

In cybersecurity engineering, complete security is an ongoing lifecycle rather than a one-time achievement.  
While SecureDocs successfully remediates the major OWASP Top 10 web application vulnerabilities (such as IDOR, CSRF, arbitrary file upload, path traversal, and missing security headers), the current implementation has several architectural and operational limitations that are documented below:

### 1. In-Depth Malware & Active Payload Scanning
- **Current Control:** The application verifies file extensions via an allowlist and inspects binary file signatures ("magic bytes") to verify that files match their claimed type (e.g., `%PDF-`, `\x89PNG`).
- **Limitation:** Magic byte validation only confirms the file structure; it does not analyze whether a valid PDF contains embedded JavaScript, malicious action scripts, or heap-spray exploits. Similarly, valid image files could conceal polyglot payloads.
- **Future Work:** Integrate an asynchronous antivirus and malware scanning engine (such as open-source **ClamAV**) or a cloud-based sandboxing service (e.g., VirusTotal API) that quarantines uploaded files until scanned.

### 2. Rate Limiting & Account Lockout
- **Current Control:** Passwords are securely hashed with salted Scrypt/PBKDF2.
- **Limitation:** The `/login` endpoint currently lacks rate limiting or account lockout mechanisms. An attacker with high bandwidth could conduct automated credential stuffing or dictionary attacks against user accounts.
- **Future Work:** Implement IP- and user-based rate limiting using **Flask-Limiter** backed by an in-memory cache like **Redis**, enforcing temporary lockout and exponential backoff after five failed attempts.

### 3. Server Header Disclosure in Local Development
- **Current Control:** Flask's `@app.after_request` attempts to strip the `Server` header (`resp.headers.pop('Server', None)`).
- **Limitation:** The local Flask development server uses Werkzeug's `WSGIRequestHandler`, which re-injects `Server: Werkzeug/3.0.4 Python/3.13.7` at the raw HTTP socket layer during response transmission.
- **Remediation in Production:** In a production deployment, the application runs behind a dedicated reverse proxy (such as Nginx) configured with `server_tokens off;` and `proxy_hide_header Server;`.

### 4. Plaintext HTTP vs. Production HTTPS / HSTS
- **Current Control:** Session cookies are configured with `HttpOnly=True` and `SameSite=Lax`. `SESSION_COOKIE_SECURE` is wired to the `COOKIE_SECURE` environment variable.
- **Limitation:** In the local evaluation environment (`http://127.0.0.1:5000`), traffic is transmitted over unencrypted HTTP. Therefore, `Strict-Transport-Security` (HSTS) cannot be enabled because browsers reject HSTS over plain HTTP per RFC 6797.
- **Future Work:** Deploy behind a TLS reverse proxy with automated Let's Encrypt certificates, enabling `Strict-Transport-Security: max-age=31536000; includeSubDomains` and setting `SESSION_COOKIE_SECURE = True`.

### 5. Single-Node Database Architecture
- **Current Control:** SQLite 3 (`data/securedocs.db`) with relational foreign keys and prepared SQL statements.
- **Limitation:** SQLite is a serverless, file-based database. It does not provide network-level access controls, row-level security policies, or concurrent high-volume write scalability.
- **Future Work:** Migrate to an enterprise relational database such as **PostgreSQL**, leveraging connection pooling, transparent data encryption (TDE), and automated database backups.

### 6. Two-Factor Authentication (2FA / MFA)
- **Current Control:** Single-factor authentication using username and hashed password.
- **Limitation:** If user credentials are compromised via phishing or credential stuffing, the attacker gains direct access to the user's documents.
- **Future Work:** Implement Time-Based One-Time Password (TOTP) multi-factor authentication (e.g., via Google Authenticator or PyOTP).

---

## 2. Roadmap for Enterprise Production Deployment

```
[ Internet / Public Clients ]
              │
              ▼
    ┌───────────────────┐
    │  Cloudflare WAF   │ (DDoS protection, Geo-blocking, WAF rules)
    └─────────┬─────────┘
              │ HTTPS (TLS 1.3)
              ▼
    ┌───────────────────┐
    │   Nginx Proxy     │ (TLS termination, HSTS, server_tokens off, rate limiting)
    └─────────┬─────────┘
              │ Unix Socket / Internal Network
              ▼
    ┌───────────────────┐
    │ Gunicorn Workers  │ (WSGI Application Server running SecureDocs)
    └─────────┬─────────┘
              │
         ┌────┴──────────────────────────┐
         ▼                               ▼
┌──────────────────┐           ┌──────────────────┐
│ PostgreSQL DB    │           │ Asynchronous     │
│ (Encrypted at    │           │ Malware Scanner  │
│  rest)           │           │ (ClamAV Worker)  │
└──────────────────┘           └──────────────────┘
```
