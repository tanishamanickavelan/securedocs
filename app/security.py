"""Hardened-mode validation helpers (used only when SECUREDOCS_MODE=hardened)."""
from werkzeug.utils import secure_filename

ALLOWED_EXT = {"txt", "pdf", "png", "jpg", "jpeg"}
EXT_MIME = {"txt": "text/plain", "pdf": "application/pdf", "png": "image/png",
            "jpg": "image/jpeg", "jpeg": "image/jpeg"}
ALLOWED_MIME = set(EXT_MIME.values())
# "Magic bytes": the first bytes of a real file identify its true format.
SIGNATURES = {"png": b"\x89PNG\r\n\x1a\n", "jpg": b"\xff\xd8\xff",
              "jpeg": b"\xff\xd8\xff", "pdf": b"%PDF-"}


def validate_upload(filename, data):
    """Return (extension, mime) or raise ValueError with a user-safe message."""
    safe = secure_filename(filename or "")
    if "." not in safe:
        raise ValueError("File must have an extension.")
    ext = safe.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_EXT:                       # 1. extension allowlist
        raise ValueError("This file type is not allowed. Allowed: txt, pdf, png, jpg.")
    if not data:
        raise ValueError("File is empty.")
    if ext == "txt":                                 # 2. content check (server-side)
        if b"\x00" in data:
            raise ValueError("File content is not valid text.")
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            raise ValueError("File content is not valid UTF-8 text.")
    elif not data.startswith(SIGNATURES[ext]):
        raise ValueError("File content does not match its extension.")
    return ext, EXT_MIME[ext]                        # MIME comes from US, not the client
