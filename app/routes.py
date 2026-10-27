import datetime
import logging
import mimetypes
import os
import re
import uuid
from functools import wraps
from flask import (Blueprint, abort, current_app as app, flash, jsonify, redirect,
                   render_template, request, send_file, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from .db import get_db
from .security import ALLOWED_MIME, validate_upload

bp = Blueprint("main", __name__)
log = logging.getLogger("securedocs")


def hardened():
    return app.config["MODE"] == "hardened"


def login_required(view):
    @wraps(view)
    def wrapped(*a, **k):
        if "user_id" not in session:
            return redirect(url_for("main.login"))
        return view(*a, **k)
    return wrapped


def get_doc(doc_id):
    """Fetch a document. FIX for IDOR: hardened mode restricts the query to the owner."""
    if hardened():
        row = get_db().execute("SELECT * FROM documents WHERE id=? AND owner_id=?",
                               (doc_id, session["user_id"])).fetchone()
    else:  # VULN: any logged-in user can fetch any id
        row = get_db().execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if row is None:
        abort(404, "Document not found.")
    return row


@bp.route("/health")
def health():
    return jsonify(status="ok", mode=app.config["MODE"])


@bp.route("/")
def index():
    return redirect(url_for("main.dashboard" if "user_id" in session else "main.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form.get("username", "").strip(), request.form.get("password", "")
        if hardened() and not (re.fullmatch(r"[A-Za-z0-9_]{3,32}", u) and len(p) >= 8):
            flash("Username: 3-32 letters/digits/_ . Password: at least 8 characters.", "danger")
        elif not u or not p:
            flash("Username and password are required.", "danger")
        else:
            try:
                db = get_db()
                db.execute("INSERT INTO users(username,password_hash) VALUES(?,?)",
                           (u, generate_password_hash(p)))
                db.commit()
                flash("Account created. Please log in.", "success")
                return redirect(url_for("main.login"))
            except Exception:
                flash("That username is already taken.", "danger")
    return render_template("auth.html", title="Register", action="register")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        row = get_db().execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
            csrf = session.get("csrf_token")
            session.clear()                     # avoid session fixation
            if csrf:
                session["csrf_token"] = csrf
            session["user_id"], session["username"] = row["id"], row["username"]
            log.info("login ok user=%s", u)
            return redirect(url_for("main.dashboard"))
        log.warning("login failed user=%s", u[:32])
        flash("Invalid username or password.", "danger")
    return render_template("auth.html", title="Login", action="login")


@bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("main.login"))


@bp.route("/dashboard")
@login_required
def dashboard():
    docs = get_db().execute("SELECT * FROM documents WHERE owner_id=? ORDER BY id DESC",
                            (session["user_id"],)).fetchall()
    return render_template("dashboard.html", docs=docs)


@bp.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Please choose a file.", "danger")
        return redirect(url_for("main.dashboard"))
    upload_dir = app.config["UPLOAD_DIR"]
    if hardened():
        try:
            data = f.read()
            ext, mime = validate_upload(f.filename, data)
        except ValueError as e:
            log.warning("upload rejected name=%r reason=%s", f.filename[:60], e)
            flash(str(e), "danger")
            return redirect(url_for("main.dashboard"))
        stored = uuid.uuid4().hex + "." + ext              # random name, we choose the path
        with open(os.path.join(upload_dir, stored), "wb") as fh:
            fh.write(data)
        display, size = secure_filename(f.filename), len(data)
    else:
        # VULN 1: trusts client Content-Type, never checks the extension or content
        if f.mimetype not in ALLOWED_MIME:
            flash("Only text, PDF and image files are allowed.", "danger")
            return redirect(url_for("main.dashboard"))
        # VULN 2: uses the client-supplied filename directly (path traversal / overwrite)
        stored = f.filename
        path = os.path.join(upload_dir, stored)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        f.save(path)
        display, mime, size = f.filename, f.mimetype, os.path.getsize(path)
    db = get_db()
    db.execute("INSERT INTO documents(owner_id,original_name,stored_name,mime,size,uploaded_at)"
               " VALUES(?,?,?,?,?,?)", (session["user_id"], display, stored, mime, size,
               datetime.datetime.now().strftime("%Y-%m-%d %H:%M")))
    db.commit()
    log.info("upload ok user=%s stored=%s", session["username"], stored)
    flash("File uploaded successfully.", "success")
    return redirect(url_for("main.dashboard"))


@bp.route("/download/<int:doc_id>")
@login_required
def download(doc_id):
    d = get_doc(doc_id)
    if hardened():
        return send_from_directory(app.config["UPLOAD_DIR"], d["stored_name"], as_attachment=True,
                                   download_name=d["original_name"], mimetype=d["mime"])
    path = os.path.join(app.config["UPLOAD_DIR"], d["stored_name"])
    if not os.path.isfile(path):
        abort(404, "File missing on disk.")
    return send_file(path, as_attachment=True, download_name=os.path.basename(d["original_name"]))


@bp.route("/preview/<int:doc_id>")
@login_required
def preview(doc_id):
    d = get_doc(doc_id)
    if hardened():
        if d["mime"] not in ("image/png", "image/jpeg", "text/plain"):
            flash("Preview is only available for images and text files.", "info")
            return redirect(url_for("main.dashboard"))
        resp = send_from_directory(app.config["UPLOAD_DIR"], d["stored_name"], mimetype=d["mime"])
        resp.headers["Content-Security-Policy"] = "sandbox; default-src 'none'; img-src 'self'"
        return resp
    path = os.path.join(app.config["UPLOAD_DIR"], d["stored_name"])
    if not os.path.isfile(path):
        abort(404, "File missing on disk.")
    # VULN 3: content type guessed from the attacker-controlled extension, served inline
    return send_file(path, mimetype=mimetypes.guess_type(path)[0] or "application/octet-stream")


@bp.route("/delete/<int:doc_id>", methods=["POST"])
@login_required
def delete(doc_id):
    d = get_doc(doc_id)
    try:
        os.remove(os.path.join(app.config["UPLOAD_DIR"], d["stored_name"]))
    except OSError:
        pass
    db = get_db()
    db.execute("DELETE FROM documents WHERE id=?", (doc_id,))
    db.commit()
    log.info("delete user=%s doc=%s", session["username"], doc_id)
    flash("Document deleted.", "success")
    return redirect(url_for("main.dashboard"))
