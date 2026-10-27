"""Automated checks for BOTH modes. Run:  python -m pytest -v"""
import io
import os
import re
import pytest
from app import create_app

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def make(tmp_path, mode):
    cfg = dict(MODE=mode, TESTING=True, DATA_DIR=str(tmp_path), SECRET_KEY="test-key",
               LAB_ACK="I_AM_LOCAL_AND_ISOLATED")
    cfg["UPLOAD_DIR"] = str(tmp_path / "uploads")
    return create_app(cfg)


def token(client):
    html = client.get("/login").get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def login(client, user, pw):
    return client.post("/login", data={"username": user, "password": pw, "csrf_token": token(client)})


def up(client, name, data, ctype):
    return client.post("/upload", data={"file": (io.BytesIO(data), name, ctype), "csrf_token": token(client)},
                       content_type="multipart/form-data", follow_redirects=True)


@pytest.fixture
def hard(tmp_path):
    app = make(tmp_path, "hardened"); app.test_client_ = app.test_client(); return app


@pytest.fixture
def vuln(tmp_path):
    return make(tmp_path, "vulnerable")


# ---------------- HARDENED ----------------
def test_health_and_headers(hard):
    c = hard.test_client(); r = c.get("/health")
    assert r.json["mode"] == "hardened"
    for h in ("Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"):
        assert h in r.headers


def test_h_rejects_disallowed_extension(hard):
    c = hard.test_client(); login(c, "alice", "Alice@12345")
    assert b"not allowed" in up(c, "page.html", b"<h1>x</h1>", "text/plain").data


def test_h_rejects_mime_spoof(hard):
    c = hard.test_client(); login(c, "alice", "Alice@12345")
    assert b"does not match" in up(c, "fake.png", b"just text, not a png", "image/png").data


def test_h_accepts_valid_and_randomizes_name(hard):
    c = hard.test_client(); login(c, "alice", "Alice@12345")
    assert b"uploaded successfully" in up(c, "pic.png", PNG, "image/png").data
    names = os.listdir(hard.config["UPLOAD_DIR"])
    assert "pic.png" not in names and any(re.fullmatch(r"[0-9a-f]{32}\.png", n) for n in names)


def test_h_traversal_name_is_neutralised(hard):
    c = hard.test_client(); login(c, "alice", "Alice@12345")
    up(c, "../../escape.txt", b"harmless", "text/plain")
    assert not os.path.exists(os.path.join(hard.config["DATA_DIR"], "escape.txt"))
    assert not os.path.exists(os.path.join(os.path.dirname(hard.config["DATA_DIR"]), "escape.txt"))


def test_h_oversize_rejected(hard):
    c = hard.test_client(); login(c, "alice", "Alice@12345")
    r = up(c, "big.txt", b"a" * (3 * 1024 * 1024), "text/plain")
    assert r.status_code == 413


def test_h_idor_blocked(hard):
    c = hard.test_client(); login(c, "bob", "Bob@12345")
    assert c.get("/download/1").status_code == 404      # doc 1 belongs to alice
    assert c.get("/preview/1").status_code == 404
    assert c.post("/delete/1", data={"csrf_token": token(c)}).status_code == 404


def test_h_csrf_required(hard):
    c = hard.test_client(); login(c, "alice", "Alice@12345")
    assert c.post("/delete/1", data={}).status_code == 400


def test_h_password_is_hashed(hard):
    import sqlite3
    row = sqlite3.connect(hard.config["DATABASE"]).execute("SELECT password_hash FROM users").fetchone()
    assert "Alice@12345" not in row[0] and row[0].startswith(("scrypt", "pbkdf2"))


def test_h_download_is_attachment(hard):
    c = hard.test_client(); login(c, "alice", "Alice@12345")
    r = c.get("/download/1")
    assert r.status_code == 200 and "attachment" in r.headers["Content-Disposition"]


def test_h_sri_attribute_present(hard):
    c = hard.test_client()
    html = c.get("/login").get_data(as_text=True)
    assert 'integrity="sha384-' in html
    assert 'crossorigin="anonymous"' in html


# ---------------- VULNERABLE (expected weaknesses) ----------------
def test_v_refuses_without_ack(tmp_path):
    with pytest.raises(RuntimeError):
        create_app(dict(MODE="vulnerable", TESTING=True, DATA_DIR=str(tmp_path), LAB_ACK=""))


def test_v_accepts_html_with_spoofed_mime(vuln):
    c = vuln.test_client(); login(c, "alice", "Alice@12345")
    assert b"uploaded successfully" in up(c, "page.html", b"<h1>benign</h1>", "text/plain").data
    r = c.get("/preview/3")
    assert r.mimetype == "text/html"                    # served as HTML -> unsafe serving


def test_v_path_traversal_writes_outside_upload_dir(vuln):
    c = vuln.test_client(); login(c, "alice", "Alice@12345")
    up(c, "../traversal_demo.txt", b"harmless", "text/plain")
    assert os.path.exists(os.path.join(vuln.config["DATA_DIR"], "traversal_demo.txt"))


def test_v_idor_download_and_delete(vuln):
    c = vuln.test_client(); login(c, "bob", "Bob@12345")
    assert c.get("/download/1").status_code == 200       # alice's doc
    assert c.post("/delete/1").status_code == 302        # no owner check, no CSRF token


def test_v_no_security_headers(vuln):
    r = vuln.test_client().get("/health")
    assert "Content-Security-Policy" not in r.headers and "X-Content-Type-Options" not in r.headers
