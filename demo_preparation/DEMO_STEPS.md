# SecureDocs — Step-by-Step Demonstration Walkthrough

This document contains the exact browser steps and Windows PowerShell commands for your live project evaluation.  
All commands are pre-tested and verified.

---

## Pre-Check: Ensure the Application is Running

Open Windows PowerShell and check that SecureDocs is active on port 5000:

```powershell
curl.exe -s http://127.0.0.1:5000/health
```

**Expected output:**
```json
{"mode":"hardened","status":"ok"}
```

*(If the server is not running, start it using:)*
```powershell
Set-Location "D:\Downloads\securedocs\securedocs"
$env:SECUREDOCS_MODE="hardened"
.\.venv\Scripts\python.exe -m flask --app app run --port 5000
```

---

## Demo Step 1: Insecure Direct Object References (IDOR) Defense

**Goal:** Demonstrate that Alice's confidential document cannot be accessed or enumerated by Bob.

### Browser Steps:
1. Open your browser and navigate to:  
   `http://127.0.0.1:5000/login`
2. Log in with Bob's credentials:
   - **Username:** `bob`
   - **Password:** `Bob@12345`
3. Bob arrives at his dashboard (`/dashboard`) and sees only his own document (`bob-notes.txt`, Document ID 2).
4. Now, manually change the URL in the address bar to request Alice's private file (Document ID 1):  
   `http://127.0.0.1:5000/download/1`
5. **Observed Result:**  
   The page displays **404 Not Found** (*"Document not found"*).

### PowerShell Verification:
Run this command to show the examiner the exact HTTP status returned to Bob:
```powershell
python -c "import urllib.request, urllib.parse, http.cookiejar; cj = http.cookiejar.CookieJar(); op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj)); html = op.open('http://127.0.0.1:5000/login').read().decode(); import re; tok = re.search(r'name=\"csrf_token\" value=\"([^\"]+)\"', html).group(1); op.open('http://127.0.0.1:5000/login', data=urllib.parse.urlencode({'username':'bob','password':'Bob@12345','csrf_token':tok}).encode()); r = op.open('http://127.0.0.1:5000/download/1')"
```
*(Throws `urllib.error.HTTPError: HTTP Error 404: NOT FOUND`, confirming protection.)*

---

## Demo Step 2: File Upload Defense (Extension & Magic Bytes)

**Goal:** Demonstrate that file upload attacks are caught by server-side allowlists and binary signature checks.

### Part A: Disallowed Extension (.exe)
1. In the browser, while logged into the dashboard, click **Browse...** or **Choose File**.
2. Select any non-allowed file (or create a dummy `malicious.exe`):
   ```powershell
   "MZ_malicious_code" | Out-File -Encoding ascii D:\Downloads\securedocs\securedocs\malicious.exe
   ```
3. Attempt to upload `malicious.exe`.
4. **Observed Result:**  
   The dashboard rejects the upload with a red banner:  
   **"This file type is not allowed. Allowed: txt, pdf, png, jpg."**

### Part B: Magic Bytes Spoofing Bypass Attempt (`fake.pdf`)
1. In the dashboard, click **Choose File** and select the existing `fake.pdf` located at:  
   `D:\Downloads\securedocs\securedocs\fake.pdf`  
   *(This is a plain text file renamed with a `.pdf` extension.)*
2. Click **Upload**.
3. **Observed Result:**  
   The server inspects the binary header, detects that the `%PDF-` signature is missing, and displays:  
   **"File content does not match its extension."**

---

## Demo Step 3: Security Headers & Cookie Flags

**Goal:** Demonstrate modern browser hardening and defensive HTTP headers.

### PowerShell Command:
Execute this one-line command to display the live response headers:
```powershell
curl.exe -i http://127.0.0.1:5000/login
```

### Key Headers to Point Out to Examiners:
1. `Content-Security-Policy`: `default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; ...`
2. `X-Content-Type-Options: nosniff` (Stops MIME-sniffing attacks)
3. `X-Frame-Options: DENY` (Blocks framing and clickjacking)
4. `Referrer-Policy: no-referrer` (Prevents URL parameter leakage)
5. `Cache-Control: no-store` (Prevents sensitive document caching)
6. `Set-Cookie: session=...; HttpOnly; Path=/; SameSite=Lax` (Protects against session theft and cross-site requests)

---

## Demo Step 4: Automated Verification Suite

**Goal:** Demonstrate 100% automated test coverage in under 6 seconds.

### PowerShell Command:
Run the pytest suite:
```powershell
Set-Location "D:\Downloads\securedocs\securedocs"
py -m pytest -v
```

**Expected output:**
```text
tests/test_app.py::test_health_and_headers PASSED
tests/test_app.py::test_h_rejects_disallowed_extension PASSED
tests/test_app.py::test_h_rejects_mime_spoof PASSED
tests/test_app.py::test_h_accepts_valid_and_randomizes_name PASSED
tests/test_app.py::test_h_traversal_name_is_neutralised PASSED
tests/test_app.py::test_h_oversize_rejected PASSED
tests/test_app.py::test_h_idor_blocked PASSED
tests/test_app.py::test_h_csrf_required PASSED
tests/test_app.py::test_h_password_is_hashed PASSED
tests/test_app.py::test_h_download_is_attachment PASSED
tests/test_app.py::test_h_sri_attribute_present PASSED
tests/test_app.py::test_v_refuses_without_ack PASSED
tests/test_app.py::test_v_accepts_html_with_spoofed_mime PASSED
tests/test_app.py::test_v_path_traversal_writes_outside_upload_dir PASSED
tests/test_app.py::test_v_idor_download_and_delete PASSED
tests/test_app.py::test_v_no_security_headers PASSED

============================= 16 passed in 5.13s ==============================
```

---

## Quick Reference Summary Table for Examiners

| Demonstration | Attack Attempted | Security Control in Hardened Mode |
|---|---|---|
| **Demo 1** | IDOR: Bob accesses Alice's `/download/1` | Query enforces `WHERE id=? AND owner_id=?` -> returns **HTTP 404** |
| **Demo 2A** | Disallowed file extension (`.exe`) | Extension allowlist in `security.py` -> **Rejected** |
| **Demo 2B** | Magic-bytes spoofing (`fake.pdf`) | Binary header inspection (`%PDF-`) -> **Rejected** |
| **Demo 3** | Clickjacking & MIME-confusion | Headers: CSP, nosniff, DENY, no-store, HttpOnly, SameSite=Lax |
| **Demo 4** | Full regression testing | 16 automated tests verified in 5 seconds via `pytest` |
