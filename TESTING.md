# Vulnerability walkthroughs (Vulnerable :5001 vs Hardened :5000)

**Tool setup.** Burp: Proxy > Intercept > *Open browser* (built-in, already proxied) > browse to http://127.0.0.1:5001. Proxy > HTTP history lists requests; right-click > *Send to Repeater*; edit; *Send*. ZAP: *Quick Start > Manual Explore* > URL http://127.0.0.1:5001 > *Launch Browser*; passive scan runs automatically (Alerts tab). Active scan only on your own lab: right-click site > Attack > Active Scan. DevTools: F12 > Network (tick *Preserve log*), Application > Cookies.
Log in as alice first. Test files are harmless text. ZAP will NOT find the authorization (IDOR) or upload-logic flaws on its own; those need manual Burp/DevTools tests.

| # | Flaw | Where (code) | Harmless test | Vulnerable result | Hardened result | Fix (in `app/routes.py` unless noted) |
|---|------|-------------|---------------|-------------------|-----------------|-----|
| 1 | Extension not validated | `upload()` else-branch | Create `page.html` containing `<h1>benign</h1>`. Upload it. In Burp Repeater set part header `Content-Type: text/plain`. | "uploaded successfully"; preview renders as HTML (Response `Content-Type: text/html`) | Flash: "not allowed" | `security.validate_upload()` extension allowlist |
| 2 | Trusts client MIME | same | Upload `fake.png` containing the words "not an image" with `Content-Type: image/png` | Accepted | "File content does not match its extension" | magic-byte check in `validate_upload()` |
| 3 | No size limit | `create_app()` `MAX_CONTENT_LENGTH` | PowerShell: `fsutil file createnew big.txt 3145728` then upload (text file of zeros) | Accepted | HTTP 413 (note: zeros also fail text check; use Repeater to see the 413 first) | `MAX_CONTENT_LENGTH = 2 MB` |
| 4 | Filename path traversal | `upload()` `stored = f.filename` | In Repeater change `filename="note.txt"` to `filename="../traversal_demo.txt"` | File lands in `/data` (one level above `/data/uploads`): `docker compose exec vulnerable ls /data` | Saved as random `<32hex>.txt` inside uploads | `uuid4().hex + ext`, `secure_filename()` for display |
| 5 | Broken authorization (IDOR) | `get_doc()` | Log in as **bob**, open `/download/1` (alice's file); in Repeater try `/preview/1` and POST `/delete/1` | 200 + alice's content; delete succeeds | 404 for all three | query includes `AND owner_id=?` |
| 6 | No CSRF protection | `before_request csrf_protect` | Repeater: POST `/delete/<id>` with no `csrf_token` field | 302, deleted | 400 "CSRF token missing or invalid" | per-session token + `compare_digest` |
| 7 | Missing security headers | `after_request headers` | DevTools > Network > click request > Response Headers; ZAP passive alerts | No CSP / nosniff / X-Frame-Options | All present | `after_request` hook |
| 8 | Unsafe file serving | `preview()` | Open preview of the uploaded `.html` from test 1 | Rendered as a live page in the app's origin | Only png/jpg/txt previewed, with `sandbox` CSP; downloads are `attachment` | allowlisted preview + `Content-Disposition` |
| 9 | Cookie flags | `create_app()` | DevTools > Application > Cookies > `session` | Flask default (HttpOnly yes, no SameSite) | HttpOnly + SameSite=Lax (+ Secure when `COOKIE_SECURE=1` behind HTTPS) | config keys |

**To "apply the fix" live:** the fixes are the `hardened()` branches. Show the vulnerable branch in the editor, then repeat the same request against http://127.0.0.1:5000 to show the secure response. (Optionally edit the vulnerable branch to match, run `docker compose --profile lab up -d --build`, retest.)

**Evidence to capture per test:** Burp request+response pair (both modes), DevTools Network headers tab, dashboard screenshot, `docker compose logs` lines such as `upload rejected name='page.html' reason=...`.
**Automated proof:** `python -m pytest -v` (15 tests: 10 hardened controls, 5 vulnerable behaviours).
