# SecureDocs — Comprehensive Viva Examination Questions & Answers

This document prepares you for examiner and professor questions during your project defense.  
The answers are phrased in clear, concise, and academically sound English.

---

### Q1: What is the main objective of your project?
**Answer:**  
"The objective of SecureDocs is to conduct a practical web application security assessment on a document management portal based on the OWASP Top 10 framework, identify vulnerabilities like IDOR, CSRF, insecure file uploads, and missing security headers, and implement server-side code remediations to harden the application against real-world attacks."

---

### Q2: What is an Insecure Direct Object Reference (IDOR), and how did you remediate it?
**Answer:**  
"An IDOR occurs when an application exposes a direct reference to an internal database object (like a document ID `doc_id=1`) and fails to verify whether the requesting user is authorized to access that object.  
In our vulnerable code, any user could view document 1 using `SELECT * FROM documents WHERE id=?`.  
We remediated this in `app/routes.py` by adding the session user check:  
`SELECT * FROM documents WHERE id=? AND owner_id=?`  
If no row is returned, the app aborts with HTTP 404."

---

### Q3: Why does your application return HTTP 404 instead of HTTP 403 when Bob attempts to access Alice's document?
**Answer:**  
"Returning HTTP 403 (Forbidden) tells an attacker that the document exists, but they do not have permission to view it. This enables **information disclosure and object enumeration**.  
By returning HTTP 404 (Not Found), the application conceals whether the document ID actually exists, giving the attacker zero useful intelligence."

---

### Q4: How does Cross-Site Request Forgery (CSRF) work, and how does your app prevent it?
**Answer:**  
"CSRF occurs when a malicious third-party site tricks a victim's browser into submitting an unauthorized request to our app where the victim is already authenticated, taking advantage of automatic cookie transmission.  
We remediated this using the **Synchronizer Token Pattern**:
1. When a session begins, a random 16-byte cryptographic token is generated and stored in `session['csrf_token']`.
2. This token is injected into all HTML forms.
3. On every state-changing POST request, our `@app.before_request` hook validates the submitted token against the session token using `secrets.compare_digest`. If the token is missing or mismatched, the request is aborted with HTTP 400."

---

### Q5: Why do you use `secrets.compare_digest` instead of `==` for CSRF token comparison?
**Answer:**  
"The standard equality operator `==` in Python short-circuits as soon as the first mismatched byte is found. This can allow an attacker to measure minuscule response time differences and perform a **timing attack** to guess the token byte-by-byte.  
`secrets.compare_digest` performs constant-time comparison, meaning it takes the same amount of time regardless of how many bytes match, neutralizing timing attacks."

---

### Q6: Why can you never trust the `Content-Type` header sent by the client during file upload?
**Answer:**  
"The client controls the HTTP request completely. An attacker using Burp Suite, cURL, or Python can easily modify the multipart `Content-Type` header to `application/pdf` or `image/png` while uploading an executable script like a `.php`, `.exe`, or `.html` file.  
Therefore, the server must validate both the file extension and the actual binary file contents independently."

---

### Q7: What are "magic bytes" (file signatures), and how do they protect the application?
**Answer:**  
"Magic bytes are the specific first few bytes of a file that identify its true file format, regardless of its extension. For example:
- A PNG file always starts with `\x89PNG\r\n\x1a\n`
- A JPEG file starts with `\xff\xd8\xff`
- A PDF file starts with `%PDF-`  
In `app/security.py`, if a user uploads a text file renamed to `fake.pdf`, our server reads the binary header, detects that it does not start with `%PDF-`, and rejects the upload with an error."

---

### Q8: Why are uploaded files stored outside the web root (`static/`)?
**Answer:**  
"If files are stored inside the public `static/` or web root directory, web servers may execute them (e.g., executing PHP or CGI scripts) or render HTML files directly in the application origin, creating a **Stored Cross-Site Scripting (XSS)** vulnerability.  
By storing uploads outside the web root in `/data/uploads` and serving them exclusively through a controlled Python endpoint using `send_from_directory` with `Content-Disposition: attachment`, files cannot be directly requested or executed by the web server."

---

### Q9: Why does your application rename uploaded files to random UUIDs?
**Answer:**  
"Using the original filename exposes the application to **path traversal attacks** (like `../../malicious.txt`) and filename collisions or overwrites.  
By generating a random 32-character hexadecimal UUID (`uuid.uuid4().hex + '.' + ext`), the internal storage path is completely decoupled from user input, preventing directory traversal and file overwriting. The original filename is stored in SQLite strictly for UI display after sanitization with `secure_filename()`."

---

### Q10: What does the `X-Content-Type-Options: nosniff` header do?
**Answer:**  
"By default, some web browsers attempt to guess or 'sniff' the MIME type of a downloaded resource if they think the declared `Content-Type` is incorrect. An attacker can exploit this by uploading an image containing JavaScript and getting the browser to interpret it as a script.  
`X-Content-Type-Options: nosniff` forces the browser to strictly adhere to the `Content-Type` declared by the server and never attempt MIME sniffing."

---

### Q11: What is Clickjacking, and how does your application prevent it?
**Answer:**  
"Clickjacking is an attack where a malicious site embeds our web application inside an invisible `<iframe>` and tricks the user into clicking buttons on our site without their knowledge.  
We prevent this using two headers:
1. `X-Frame-Options: DENY`: Tells browsers that our pages must never be framed by any website.
2. `Content-Security-Policy: frame-ancestors 'none'`: The modern CSP equivalent that completely disables framing."

---

### Q12: What is Sub Resource Integrity (SRI), and how did you verify it in your project?
**Answer:**  
"Sub Resource Integrity (SRI) is a browser security mechanism where external scripts or stylesheets loaded from CDNs include an `integrity` cryptographic hash attribute (e.g., `integrity='sha384-...'`) and `crossorigin='anonymous'`.  
When the browser downloads the file, it computes the hash and compares it with the declared hash. If an attacker compromises the CDN and alters the file, the hash fails, and the browser refuses to load it.  
In our project, we verified that the Bootstrap CDN link includes the official SHA-384 hash and wrote an automated test `test_h_sri_attribute_present` to guarantee its presence."

---

### Q13: Why did OWASP ZAP show an alert for "Sub Resource Integrity Attribute Missing" even after you added the integrity tag?
**Answer:**  
"In OWASP ZAP, passive scan alerts are immutable records attached to the specific historical HTTP request/response ID where they were first detected.  
The alert in ZAP's UI was tied to older messages (e.g., Message 9 and Message 58) recorded during an initial crawl before the template was updated.  
When we proxied a fresh request through ZAP, ZAP generated zero SRI alerts, proving that the fix was active and that the remaining alert was simply a historical record of the earlier scan."

---

### Q14: Why does your server expose the `Server: Werkzeug/3.0.4 Python/3.13.7` header, and why couldn't Flask's `after_request` remove it?
**Answer:**  
"Flask's `@app.after_request` hook operates inside the WSGI application layer. However, Werkzeug's HTTP server (`WSGIRequestHandler`) adds the `Server` header at the raw socket transport layer when formatting the HTTP response lines, after Flask has finished execution.  
In a production deployment, this is properly remediated at the reverse proxy layer (such as Nginx) by configuring `server_tokens off;` and `proxy_hide_header Server;`."

---

### Q15: Why is Strict-Transport-Security (HSTS) not enabled in your local test environment?
**Answer:**  
"According to RFC 6797 § 7.2, HSTS headers must **never** be sent over plaintext HTTP. If sent over HTTP, browsers are required to ignore them because an unencrypted connection could be modified by a man-in-the-middle attacker.  
HSTS is strictly a TLS/HTTPS control. In production, TLS termination at the reverse proxy automatically enables HSTS and sets `SESSION_COOKIE_SECURE = True`."

---

### Q16: How are user passwords stored in your database?
**Answer:**  
"Passwords are never stored in plaintext. They are hashed using `werkzeug.security.generate_password_hash()`, which implements modern **scrypt** or **PBKDF2-HMAC-SHA256** with an automatic random cryptographic salt and a high work factor. This protects credentials against rainbow table attacks and offline dictionary cracking."

---

### Q17: Can automated DAST tools like OWASP ZAP find all vulnerabilities on their own?
**Answer:**  
"No. Automated dynamic tools like ZAP excel at discovering technical and configuration flaws (such as missing security headers, missing SRI hashes, or cookie flags).  
However, ZAP cannot understand business logic or authorization models. It cannot automatically recognize that Bob should not have access to Alice's document ID 1. **Authorization flaws (IDOR) and business logic bypasses require manual testing and domain-specific code design.**"

---

### Q18: What are the main limitations of your project, and what would you improve in the future?
**Answer:**  
"The main limitations are:
1. **Malware Scanning:** Magic bytes check file format, but do not scan for embedded malware or PDF exploit scripts. Production systems should integrate ClamAV.
2. **Rate Limiting:** Login is not currently protected against brute force password attacks. We would add Flask-Limiter with Redis.
3. **Infrastructure:** In production, the Flask dev server and SQLite would be replaced with Gunicorn, an Nginx reverse proxy with HTTPS/TLS certificates, and a PostgreSQL database."
