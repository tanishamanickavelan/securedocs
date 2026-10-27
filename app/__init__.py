import logging
import os
import secrets
from flask import Flask, abort, render_template, request, session
from . import db

LAB_ACK = "I_AM_LOCAL_AND_ISOLATED"
log = logging.getLogger("securedocs")


def create_app(test_config=None):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    app = Flask(__name__)
    data_dir = os.environ.get("DATA_DIR", os.path.join(os.getcwd(), "data"))
    app.config.update(
        MODE=os.environ.get("SECUREDOCS_MODE", "hardened").lower(),
        SECRET_KEY=os.environ.get("SECRET_KEY", ""),
        LAB_ACK=os.environ.get("LAB_ACK", ""),
        DATA_DIR=data_dir, SEED=True)
    if test_config:
        app.config.update(test_config)
    c = app.config
    c.setdefault("DATABASE", os.path.join(c["DATA_DIR"], "securedocs.db"))
    c.setdefault("UPLOAD_DIR", os.path.join(c["DATA_DIR"], "uploads"))  # NOT under static/
    os.makedirs(c["DATA_DIR"], exist_ok=True)

    if c["MODE"] == "vulnerable":
        # Safety interlock: refuse to start unless the operator explicitly confirms.
        if c["LAB_ACK"] != LAB_ACK:
            raise RuntimeError("Vulnerable mode refused: set LAB_ACK=%s (local isolated lab only)." % LAB_ACK)
        c["SECRET_KEY"] = c["SECRET_KEY"] or "lab-secret"
        c["MAX_CONTENT_LENGTH"] = None                     # VULN: no size limit
    elif c["MODE"] == "hardened":
        if not c["SECRET_KEY"] or c["SECRET_KEY"] == "change-me-to-a-long-random-string":
            log.warning("No strong SECRET_KEY set; generating a random one for this run.")
            c["SECRET_KEY"] = secrets.token_hex(32)
        c["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024          # 2 MB
        c["SESSION_COOKIE_HTTPONLY"] = True
        c["SESSION_COOKIE_SAMESITE"] = "Lax"
        c["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"  # set 1 behind HTTPS
    else:
        raise RuntimeError("SECUREDOCS_MODE must be 'hardened' or 'vulnerable'")

    db.init_db(app)
    app.teardown_appcontext(db.close_db)
    from .routes import bp
    app.register_blueprint(bp)

    @app.before_request
    def csrf_protect():
        if c["MODE"] == "hardened" and request.method == "POST":
            sent, real = request.form.get("csrf_token", ""), session.get("csrf_token", "")
            if not real or not secrets.compare_digest(sent, real):
                log.warning("CSRF check failed on %s", request.path)
                abort(400, "CSRF token missing or invalid.")

    @app.context_processor
    def inject():
        token = ""
        if c["MODE"] == "hardened":
            token = session.setdefault("csrf_token", secrets.token_hex(16))
        return {"mode": c["MODE"], "csrf_token": token}

    @app.after_request
    def headers(resp):
        if c["MODE"] == "hardened":
            resp.headers.setdefault("Content-Security-Policy",
                "default-src 'self'; style-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; "
                "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["X-Frame-Options"] = "DENY"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["Cache-Control"] = "no-store"
            resp.headers.pop("Server", None)
        return resp

    for code in (400, 403, 404, 413):
        app.register_error_handler(code, lambda e: (render_template(
            "error.html", code=e.code, msg=getattr(e, "description", "")), e.code))

    log.info("SecureDocs started in %s mode", c["MODE"].upper())
    return app
