# Demo script (about 18 min). Say it in your own words; these are talking points.

1. **Intro (1.5)** - "File upload is a classic risky feature. I built a portal in two modes: a deliberately weak one and a hardened one, then attacked both with Burp, ZAP and DevTools." Show: README. Evidence: title slide.
2. **Architecture (2)** - Flask, SQLite, Docker; uploads stored in `/data/uploads`, outside the web root. Show the folder tree + `docker compose ps`.
3. **Vulnerable workflow (2)** - Log in as alice at :5001, red banner, upload a normal txt, preview, download.
4. **Burp (3)** - Proxy > HTTP history, show the multipart upload; send to Repeater; change filename to `page.html`, Content-Type `text/plain`: accepted.
5. **ZAP (2)** - Passive scan results on :5001: missing CSP, nosniff, anti-clickjacking. Say clearly: "ZAP flagged headers; it did not find the IDOR or upload bypass, I found those manually."
6. **DevTools (1)** - Response headers missing; cookie flags.
7. **Selected vulns (2.5)** - Path traversal file in `/data`; bob opens `/download/1`; delete with no token.
8. **Code fixes (2)** - Open `security.py` (`validate_upload`) and `get_doc()` (owner check).
9. **Re-test (2)** - Same requests on :5000: "not allowed", "does not match", 404, 400, 413.
10. **Before/after table (1)** - TESTING.md table. Run `pytest` live: 15 passed.
11. **Docker (1)** - 127.0.0.1 binding, `--profile lab`, LAB_ACK, non-root, read-only.
12. **Conclusion (1)** - Validate server-side, never trust client data, authorize every object access, defense in depth.

**Likely questions.** *Why not trust Content-Type?* The client controls it. *Why random filenames?* Prevents traversal/overwrite and guessing. *Why magic bytes if extension is checked?* Extension is just a name; signature checks content (still not a full malware scan). *Why store outside web root?* So uploads can never be executed/served directly. *Is hardened version perfect?* No: no antivirus scan, no rate limiting, SQLite, HTTP only locally (use HTTPS + `COOKIE_SECURE=1` in production). *Does ZAP find everything?* No, authorization flaws need manual testing.
