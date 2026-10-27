# SecureDocs — 5 to 7 Minute Demonstration Script

> **Speaker Note:** Speak naturally, clearly, and with confidence. You do not need to memorize word-for-word—use this script as your conversational guide. Keep the application running in your terminal and your browser open at `http://127.0.0.1:5000`.

---

### Step 1: Introduction & Objective (Approx. 1 minute)

"Good morning / afternoon professors.

Today I am presenting **SecureDocs**, a web application security assessment and remediation project.

Our academic objective was to take a web application, understand its techniques, discover its security vulnerabilities, and implement robust engineering solutions to fix them.

For this project, I chose a document management portal. In modern cloud applications, file upload and document sharing are among the most security-sensitive features. If an application makes assumptions or trusts client data, it can expose the entire backend to Insecure Direct Object References (IDOR), Remote Code Execution, Cross-Site Scripting, and Cross-Site Request Forgery.

I designed this project with a two-mode architecture:
- A **Vulnerable Mode** that demonstrates real-world security flaws and how attackers exploit them.
- A **Hardened Mode** where defense-in-depth controls are enforced at every layer of the request lifecycle.

Let me show you how this works in practice."

---

### Step 2: Architecture & Setup (Approx. 45 seconds)

"The application is built using Python 3.13, Flask, and an SQLite database with encrypted password hashing.

A critical design choice is how files are handled:
Uploaded documents are **never** stored inside the public `static/` or web root directory. Instead, they are stored in a segregated `/data/uploads` folder, with randomly generated 32-character UUID names, completely decoupling the user's input from the filesystem.

Our application is currently running locally on port 5000 in hardened mode. Let's verify its health:
Visiting `/health` returns `status: ok` and `mode: hardened`."

---

### Step 3: Demonstration 1 — Broken Object Authorization (IDOR) (Approx. 1.5 minutes)

"The first major vulnerability we assessed was **Insecure Direct Object References**, ranked in OWASP Top 10 A01 (Broken Access Control).

In our system, user **Alice** owns Document ID 1 (`alice-notes.txt`), which contains her confidential notes.

Now, I will log in as **Bob** (`bob / Bob@12345`).

Bob has his own document, Document ID 2. But what happens if Bob maliciously tampers with the URL to view Alice's file by requesting `http://127.0.0.1:5000/download/1`?

*(Show browser returning HTTP 404 Not Found)*

Notice that Bob receives an **HTTP 404 Not Found**.

Why 404 instead of 403 Forbidden?
In the vulnerable version, the SQL query was simply:
`SELECT * FROM documents WHERE id=?`
This allowed any logged-in user to download or delete anyone else's files.

In our hardened version, in `app/routes.py`, we enforce:
`SELECT * FROM documents WHERE id=? AND owner_id=?`
By checking `session['user_id']`, if Bob asks for Document 1, the query returns nothing. We purposely return a 404 so an attacker cannot even discover whether a document ID exists. This completely neutralizes IDOR."

---

### Step 4: Demonstration 2 — Safe File Upload & Content Validation (Approx. 1.5 minutes)

"The second critical area is **File Upload Restrictions and Content Validation**.

Attackers frequently bypass file upload forms by renaming malicious files or spoofing client headers. We implemented a three-tier defense:

1. **Extension Allowlist:** If an attacker attempts to upload an executable (`malicious.exe`) or an HTML script, the application immediately rejects it with: *'This file type is not allowed.'*
2. **Binary Magic Bytes Validation:** An attacker might try to be clever by taking an executable or a plain text script and renaming it to `fake.pdf`.
Let me try uploading `fake.pdf` right now.
*(Show browser uploading fake.pdf)*
Look at the alert: *'File content does not match its extension.'*
Our backend in `security.py` inspects the first binary bytes on disk. A real PDF must begin with the `%PDF-` signature. Because `fake.pdf` lacks this signature, it is caught and rejected immediately.
3. **Storage Sanitization:** When a legitimate file like a PNG or text file is uploaded, the server never trusts the filename provided by the user. It generates a unique 128-bit UUID filename so path traversal attacks like `../../escape.txt` are completely impossible."

---

### Step 5: Demonstration 3 — CSRF, Headers & OWASP ZAP (Approx. 1.5 minutes)

"Next, we examined client-side security and HTTP headers.

1. **CSRF Protection:** State-changing requests like document deletion require a cryptographically random `csrf_token`. If an external attacker attempts to trigger a POST request without this token, our `@app.before_request` hook intercepts it and aborts with **HTTP 400 Bad Request**.
2. **Defensive Headers:** In Chrome DevTools or cURL, we can inspect our response headers:
   - `Content-Security-Policy`: restricts unauthorized scripts and framing.
   - `X-Content-Type-Options: nosniff`: prevents MIME-sniffing attacks.
   - `X-Frame-Options: DENY`: prevents clickjacking.
   - `Cache-Control: no-store`: ensures private documents are not cached on public workstations.
   - Session cookies have `HttpOnly` and `SameSite=Lax` enabled.

We also tested our application with **OWASP ZAP 2.17.0**.
ZAP identified external resources and helped us verify **Sub Resource Integrity (SRI)** on our Bootstrap CDN link (`integrity='sha384-...'`). This ensures that even if a public CDN is compromised, malicious styles cannot be injected into our users' browsers."

---

### Step 6: Automated Verification & Conclusion (Approx. 45 seconds)

"To prove that all our security fixes work reliably, we maintain an automated test suite.

*(Switch to terminal and run: `py -m pytest -v`)*

Here we have 16 automated tests covering both positive access and negative attack scenarios:
- IDOR access blocked: Passed.
- CSRF missing token blocked: Passed.
- Magic-byte spoofing rejected: Passed.
- Upload size limits enforced: Passed.
- Path traversal neutralized: Passed.
- SRI attribute verified: Passed.

All 16 tests pass in approximately 5 seconds.

To conclude: Web application security cannot rely on client-side controls or single-point checks. By combining server-side input validation, strict object-level authorization, safe filesystem separation, and modern HTTP defensive headers, we transformed an insecure application into a resilient, hardened portal.

Thank you, and I am now ready for your questions."
