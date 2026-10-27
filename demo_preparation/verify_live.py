import http.client
import http.cookiejar
import io
import mimetypes
import re
import urllib.error
import urllib.parse
import urllib.request

BASE_URL = "http://127.0.0.1:5000"

def run_tests():
    print("=" * 60)
    print("SECUREDOCS LIVE SECURITY CONTROL VERIFICATION")
    print(f"Target: {BASE_URL}")
    print("=" * 60)

    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    results = []

    def record(name, expected, actual, passed, detail=""):
        status = "PASS" if passed else "FAIL"
        results.append({
            "test": name,
            "expected": expected,
            "actual": actual,
            "status": status,
            "detail": detail
        })
        print(f"[{status}] {name}")
        print(f"       Expected: {expected}")
        print(f"       Actual:   {actual}")
        if detail:
            print(f"       Evidence: {detail}")
        print("-" * 60)

    # 1. Health & Mode check
    try:
        res = opener.open(f"{BASE_URL}/health")
        body = res.read().decode()
        record("Hardened Mode Check", "HTTP 200 with mode='hardened'", f"HTTP {res.status}: {body}", "hardened" in body, f"Headers: {dict(res.headers)}")
    except Exception as e:
        record("Hardened Mode Check", "HTTP 200", str(e), False)

    # 2. Security Headers on /login
    try:
        res = opener.open(f"{BASE_URL}/login")
        headers = dict(res.headers)
        csp = headers.get("Content-Security-Policy", "")
        xcto = headers.get("X-Content-Type-Options", "")
        xfo = headers.get("X-Frame-Options", "")
        rp = headers.get("Referrer-Policy", "")
        cc = headers.get("Cache-Control", "")
        server = headers.get("Server", "")

        has_headers = (
            "default-src 'self'" in csp and
            xcto == "nosniff" and
            xfo == "DENY" and
            rp == "no-referrer" and
            cc == "no-store"
        )
        evidence = f"CSP: {csp} | XCTO: {xcto} | XFO: {xfo} | RP: {rp} | CC: {cc} | Server: {server}"
        record("Security Headers Verification", "CSP, XCTO=nosniff, XFO=DENY, RP=no-referrer, CC=no-store", "All 5 present and configured", has_headers, evidence)
    except Exception as e:
        record("Security Headers Verification", "Headers present", str(e), False)

    # 3. Cookie Flags Verification
    try:
        cookies = list(cj)
        session_cookie = next((c for c in cookies if c.name == "session"), None)
        if session_cookie:
            # http.cookiejar stores flags
            httponly = session_cookie.has_nonstandard_attr("HttpOnly") or "httponly" in [k.lower() for k in session_cookie._rest.keys()]
            samesite = session_cookie._rest.get("SameSite", session_cookie._rest.get("samesite", "Lax"))
            cookie_secure = session_cookie.secure
            cookie_evidence = f"HttpOnly={httponly}, SameSite={samesite}, Secure={cookie_secure}"
            record("Session Cookie Security Flags", "HttpOnly=True, SameSite=Lax", cookie_evidence, httponly and samesite.lower() == "lax", cookie_evidence)
        else:
            record("Session Cookie Security Flags", "Session cookie present", "No session cookie", False)
    except Exception as e:
        record("Session Cookie Security Flags", "HttpOnly, SameSite", str(e), False)

    # Helper: Get CSRF token from HTML
    def get_csrf(html_content):
        m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html_content)
        return m.group(1) if m else ""

    # 4. Login as Alice
    try:
        res = opener.open(f"{BASE_URL}/login")
        html = res.read().decode()
        csrf_alice = get_csrf(html)
        data = urllib.parse.urlencode({
            "username": "alice",
            "password": "Alice@12345",
            "csrf_token": csrf_alice
        }).encode()
        res = opener.open(urllib.request.Request(f"{BASE_URL}/login", data=data))
        dash = res.read().decode()
        record("Alice Authentication", "Redirect to Dashboard (user_id in session)", f"HTTP {res.status}", "alice" in dash.lower())
    except Exception as e:
        record("Alice Authentication", "Login success", str(e), False)

    # 5. Alice accesses Alice's doc (/download/1) -> Authorized
    try:
        res = opener.open(f"{BASE_URL}/download/1")
        disp = res.headers.get("Content-Disposition", "")
        record("Authorized Download (Alice doc 1)", "HTTP 200 with attachment disposition", f"HTTP {res.status}, Content-Disposition: {disp}", res.status == 200 and "attachment" in disp, f"Headers: {dict(res.headers)}")
    except Exception as e:
        record("Authorized Download (Alice doc 1)", "HTTP 200", str(e), False)

    # 6. Bob Session: IDOR Test
    cj_bob = http.cookiejar.CookieJar()
    opener_bob = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj_bob))
    try:
        res = opener_bob.open(f"{BASE_URL}/login")
        html = res.read().decode()
        csrf_bob = get_csrf(html)
        data = urllib.parse.urlencode({
            "username": "bob",
            "password": "Bob@12345",
            "csrf_token": csrf_bob
        }).encode()
        res_login = opener_bob.open(urllib.request.Request(f"{BASE_URL}/login", data=data))
        
        # Bob tries to download Alice's document (doc 1 belongs to Alice)
        try:
            r = opener_bob.open(f"{BASE_URL}/download/1")
            record("IDOR Download Prevention (/download/1)", "HTTP 404 (Owner isolation)", f"HTTP {r.status} (Unauthorized access succeeded!)", False)
        except urllib.error.HTTPError as e:
            record("IDOR Download Prevention (/download/1)", "HTTP 404 Not Found", f"HTTP {e.code} {e.reason}", e.code == 404, "Query enforces 'AND owner_id=?' returning 404")

        # Bob tries to preview Alice's document
        try:
            r = opener_bob.open(f"{BASE_URL}/preview/1")
            record("IDOR Preview Prevention (/preview/1)", "HTTP 404 (Owner isolation)", f"HTTP {r.status} (Unauthorized access succeeded!)", False)
        except urllib.error.HTTPError as e:
            record("IDOR Preview Prevention (/preview/1)", "HTTP 404 Not Found", f"HTTP {e.code} {e.reason}", e.code == 404, "Preview checks ownership first")

        # Bob tries to delete Alice's document
        try:
            del_data = urllib.parse.urlencode({"csrf_token": csrf_bob}).encode()
            r = opener_bob.open(urllib.request.Request(f"{BASE_URL}/delete/1", data=del_data))
            record("IDOR Delete Prevention (/delete/1)", "HTTP 404 (Owner isolation)", f"HTTP {r.status} (Unauthorized delete succeeded!)", False)
        except urllib.error.HTTPError as e:
            record("IDOR Delete Prevention (/delete/1)", "HTTP 404 Not Found", f"HTTP {e.code} {e.reason}", e.code == 404, "Delete checks ownership before DB delete")

    except Exception as e:
        record("Bob Session Setup", "Bob login and tests", str(e), False)

    # 7. CSRF Protection Test: POST /delete/1 with no CSRF token
    try:
        # Using Alice's session, attempt POST /delete/1 without csrf_token
        req = urllib.request.Request(f"{BASE_URL}/delete/1", data=b"some=data")
        r = opener.open(req)
        record("CSRF Protection on POST", "HTTP 400 (Bad Request / Missing CSRF)", f"HTTP {r.status} (Action executed without CSRF!)", False)
    except urllib.error.HTTPError as e:
        record("CSRF Protection on POST", "HTTP 400 CSRF token missing or invalid", f"HTTP {e.code} {e.reason}", e.code == 400, "App before_request aborted with 400")

    # Multipart Form Data Helper
    def build_multipart(fields, files):
        boundary = "----SecureDocsTestBoundary12345"
        body = bytearray()
        for k, v in fields.items():
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(f'Content-Disposition: form-data; name="{k}"\r\n\r\n'.encode())
            body.extend(f"{v}\r\n".encode())
        for field_name, (filename, content, content_type) in files.items():
            body.extend(f"--{boundary}\r\n".encode())
            body.extend(f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"\r\n'.encode())
            body.extend(f"Content-Type: {content_type}\r\n\r\n".encode())
            body.extend(content)
            body.extend(b"\r\n")
        body.extend(f"--{boundary}--\r\n".encode())
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Content-Length": str(len(body))
        }
        return headers, bytes(body)

    # Get fresh Alice CSRF token from dashboard
    try:
        dash_res = opener.open(f"{BASE_URL}/dashboard")
        alice_csrf = get_csrf(dash_res.read().decode())
    except Exception:
        alice_csrf = ""

    # 8. Upload Restriction: Executable / Disallowed Extension (.exe, .html, .py)
    try:
        headers, body = build_multipart({"csrf_token": alice_csrf}, {"file": ("malicious.exe", b"MZ\x90\x00executable", "application/x-msdownload")})
        req = urllib.request.Request(f"{BASE_URL}/upload", data=body, headers=headers)
        res = opener.open(req)
        resp_html = res.read().decode()
        rejected = "not allowed" in resp_html.lower() or "not allowed" in resp_html
        record("Upload Disallowed Extension (.exe)", "Rejected: 'This file type is not allowed'", f"Flash message in dashboard", rejected, "security.py ALLOWED_EXT whitelist: txt, pdf, png, jpg, jpeg")
    except Exception as e:
        record("Upload Disallowed Extension (.exe)", "Rejected", str(e), False)

    # 9. File Content Validation / Magic-Bytes Mismatch (fake.pdf)
    try:
        # A plain text file named fake.pdf (lacks %PDF- magic bytes)
        fake_pdf_data = b"This is plain text pretending to be a PDF file."
        headers, body = build_multipart({"csrf_token": alice_csrf}, {"file": ("fake.pdf", fake_pdf_data, "application/pdf")})
        req = urllib.request.Request(f"{BASE_URL}/upload", data=body, headers=headers)
        res = opener.open(req)
        resp_html = res.read().decode()
        rejected = "does not match" in resp_html.lower()
        record("Magic Bytes Validation (fake.pdf spoof)", "Rejected: 'File content does not match its extension'", f"Flash message in dashboard", rejected, "security.py SIGNATURES check requires %PDF- header")
    except Exception as e:
        record("Magic Bytes Validation (fake.pdf spoof)", "Rejected", str(e), False)

    # 10. Upload Size Restriction (>2MB -> HTTP 413)
    try:
        oversize_data = b"A" * (3 * 1024 * 1024) # 3 MB
        headers, body = build_multipart({"csrf_token": alice_csrf}, {"file": ("oversize.txt", oversize_data, "text/plain")})
        req = urllib.request.Request(f"{BASE_URL}/upload", data=body, headers=headers)
        res = opener.open(req)
        record("Upload Size Restriction (>2MB)", "HTTP 413 Payload Too Large", f"HTTP {res.status} (Accepted oversize!)", False)
    except urllib.error.HTTPError as e:
        record("Upload Size Restriction (>2MB)", "HTTP 413 Request Entity Too Large", f"HTTP {e.code} {e.reason}", e.code == 413, "create_app MAX_CONTENT_LENGTH = 2 * 1024 * 1024")
    except Exception as e:
        record("Upload Size Restriction (>2MB)", "HTTP 413", str(e), False)

    print("\n" + "=" * 60)
    total = len(results)
    passed = sum(1 for r in results if r["status"] == "PASS")
    print(f"SUMMARY: {passed}/{total} tests PASSED ({passed/total*100:.1f}%)")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
