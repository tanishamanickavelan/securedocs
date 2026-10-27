# Security Assessment Report - SecureDocs (template)
**Scope:** local Docker lab only, dummy data. **Environment:** Windows + Docker Desktop, versions: ____ . **Tools:** Burp CE ____, ZAP ____, Browser ____.
**Architecture:** Flask app -> SQLite (`/data/securedocs.db`) + files in `/data/uploads` (not web-served).
**Method:** manual tests via Burp Repeater and DevTools; ZAP passive (+ active on lab) scan; automated pytest.

| ID | Finding | Risk (reason) | Status | Evidence |
|----|---------|---------------|--------|----------|
| F1 | Extension not validated | High (unsafe content stored/served) | Automated test VERIFIED; manual ___ | |
| F2 | Client MIME trusted | Medium | Automated VERIFIED; manual ___ | |
| F3 | No size limit | Medium (DoS) | Hardened 413 VERIFIED; vulnerable acceptance NOT separately tested | |
| F4 | Path traversal via filename | High | Automated VERIFIED; manual ___ | |
| F5 | IDOR on download/preview/delete | High (data exposure) | Automated VERIFIED; manual ___ | |
| F6 | No CSRF | Medium | Automated VERIFIED; manual ___ | |
| F7 | Missing security headers | Low-Medium | Automated VERIFIED; ZAP: ___ | |
| F8 | Inline serving of uploaded HTML | High (stored XSS in lab) | Automated VERIFIED (served as text/html); alert box NOT tested | |

**Before/after:** fill from your Burp/ZAP runs. **Root causes:** trusting client input; missing object-level authorization; no defaults for headers. **Remaining limitations:** no malware scanning, no rate limiting, no HTTPS in lab, SQLite single-node, CDN-hosted Bootstrap, Docker build and ZAP/Burp results not verified by the author. **Conclusion:** ____
Mark each row "Verified by test" only if you actually observed it.
