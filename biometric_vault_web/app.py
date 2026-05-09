from pathlib import Path
from uuid import uuid4

from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.utils import secure_filename
from PIL import Image

from modules.attack_detector import is_blocked, should_block
from modules.biometric import compare_fingerprint, fingerprint_hash
from modules.crypto import decrypt_file, encrypt_file
from modules.database import (
    add_user_fingerprint,
    block_user,
    create_file_record,
    create_user,
    find_fingerprint_owner,
    get_file_for_user,
    get_user,
    get_user_by_id,
    increment_failed_attempts,
    init_db,
    list_files,
    list_logs,
    list_user_fingerprints,
    reset_failed_attempts,
)
from modules.logger import log_event
from modules.paths import FINGERPRINT_DIR, UPLOAD_DIR, ensure_directories
from modules.watermark import embed_watermark


app = Flask(__name__)
app.secret_key = "secure-biometric-vault-demo-secret"

ACCESS_DENIED_MESSAGE = "Credentials denied."
FINGERPRINT_DENIED_MESSAGE = "Biometric credentials denied."
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"}
DOCUMENT_EXTENSIONS = {".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".json", ".png", ".jpg", ".jpeg", ".zip"}


def bootstrap() -> None:
    ensure_directories()
    init_db()


def save_upload(file_storage, directory: Path, allowed_extensions: set[str], image_only: bool = False) -> Path:
    if not file_storage or not file_storage.filename:
        raise ValueError("Please upload a file.")
    filename = secure_filename(file_storage.filename)
    suffix = Path(filename).suffix.lower()
    if suffix not in allowed_extensions:
        raise ValueError("Unsupported file type.")
    destination = directory / f"{Path(filename).stem}_{uuid4().hex[:10]}{Path(filename).suffix}"
    file_storage.save(destination)
    if image_only:
        try:
            with Image.open(destination) as image:
                image.verify()
        except Exception as exc:
            destination.unlink(missing_ok=True)
            raise ValueError("Invalid fingerprint image.") from exc
    return destination


def current_user() -> dict | None:
    user_id = session.get("user_id")
    return get_user_by_id(user_id) if user_id else None


def require_login():
    user = current_user()
    if user is None:
        flash("Please login first.", "warning")
        return None
    return user


def verify_any_user_fingerprint(user: dict, uploaded_path: Path) -> tuple[bool, str | None]:
    fingerprints = list_user_fingerprints(user["id"])
    for fingerprint in fingerprints:
        matched, candidate_hash = compare_fingerprint(fingerprint["fingerprint_hash"], uploaded_path)
        if matched:
            return True, candidate_hash
    return False, None


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        fingerprint_file = request.files.get("fingerprint")
        try:
            if not username:
                raise ValueError("Username is required.")
            saved_path = save_upload(fingerprint_file, FINGERPRINT_DIR, IMAGE_EXTENSIONS, image_only=True)
            template_hash = fingerprint_hash(saved_path)
            owner = find_fingerprint_owner(template_hash)
            if owner is not None:
                log_event(
                    username or None,
                    "REGISTER",
                    "FAILED",
                    f"Duplicate fingerprint attempted. Existing owner: {owner['username']}.",
                )
                raise ValueError(FINGERPRINT_DENIED_MESSAGE)
            watermarked_path = embed_watermark(saved_path, f"owner:{username}")
            create_user(username, template_hash, str(watermarked_path))
            log_event(username, "REGISTER", "SUCCESS", "Protected biometric template saved.")
            flash("Registration successful. You can login now.", "success")
            return redirect(url_for("login"))
        except Exception as exc:
            log_event(username or None, "REGISTER", "FAILED", str(exc))
            flash(str(exc), "danger")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET" and current_user() is not None:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        fingerprint_file = request.files.get("fingerprint")
        try:
            uploaded_path = save_upload(fingerprint_file, UPLOAD_DIR, IMAGE_EXTENSIONS, image_only=True)
            user = get_user(username)
            if user is None:
                log_event(username or None, "LOGIN", "FAILED", "Unknown username.")
                raise ValueError(ACCESS_DENIED_MESSAGE)
            if is_blocked(user):
                log_event(username, "LOGIN", "BLOCKED", "Blocked user attempted login.")
                raise ValueError(ACCESS_DENIED_MESSAGE)
            matched, _ = verify_any_user_fingerprint(user, uploaded_path)
            if not matched:
                attempts = increment_failed_attempts(username)
                log_message = f"Wrong fingerprint. Failed attempts: {attempts}/3."
                status = "FAILED"
                if should_block(attempts):
                    block_user(username)
                    status = "BLOCKED"
                    log_message = "User blocked after 3 wrong fingerprint attempts."
                log_event(username, "LOGIN", status, log_message)
                raise ValueError(ACCESS_DENIED_MESSAGE)
            reset_failed_attempts(username)
            session["user_id"] = user["id"]
            log_event(username, "LOGIN", "SUCCESS", "Fingerprint matched.")
            return redirect(url_for("dashboard"))
        except Exception as exc:
            flash(str(exc), "danger")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    return render_template(
        "dashboard.html",
        user=user,
        files=list_files(user["id"]),
        fingerprints=list_user_fingerprints(user["id"]),
    )


@app.route("/add-fingerprint", methods=["GET", "POST"])
def add_fingerprint():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        label = request.form.get("label", "").strip() or "Additional fingerprint"
        fingerprint_file = request.files.get("fingerprint")
        try:
            saved_path = save_upload(fingerprint_file, FINGERPRINT_DIR, IMAGE_EXTENSIONS, image_only=True)
            template_hash = fingerprint_hash(saved_path)
            owner = find_fingerprint_owner(template_hash)
            if owner is not None:
                if owner["user_id"] == user["id"]:
                    raise ValueError(FINGERPRINT_DENIED_MESSAGE)
                log_event(
                    user["username"],
                    "ADD_FINGERPRINT",
                    "FAILED",
                    f"Duplicate fingerprint attempted. Existing owner: {owner['username']}.",
                )
                raise ValueError(FINGERPRINT_DENIED_MESSAGE)
            watermarked_path = embed_watermark(saved_path, f"owner:{user['username']}|label:{label}")
            add_user_fingerprint(user["id"], template_hash, str(watermarked_path), label)
            log_event(user["username"], "ADD_FINGERPRINT", "SUCCESS", f"Added fingerprint: {label}.")
            flash("Fingerprint added successfully.", "success")
            return redirect(url_for("dashboard"))
        except Exception as exc:
            log_event(user["username"], "ADD_FINGERPRINT", "FAILED", str(exc))
            flash(str(exc), "danger")
    return render_template("add_fingerprint.html", user=user)


@app.route("/encrypt", methods=["GET", "POST"])
def encrypt():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        document = request.files.get("document")
        fingerprint_file = request.files.get("fingerprint")
        try:
            source_path = save_upload(document, UPLOAD_DIR, DOCUMENT_EXTENSIONS)
            fingerprint_path = save_upload(fingerprint_file, UPLOAD_DIR, IMAGE_EXTENSIONS, image_only=True)
            matched, _ = verify_any_user_fingerprint(user, fingerprint_path)
            if not matched:
                log_event(user["username"], "ENCRYPT", "FAILED", "Fingerprint mismatch.")
                raise ValueError(FINGERPRINT_DENIED_MESSAGE)
            encrypted_path = encrypt_file(source_path, user["username"], user["fingerprint_hash"])
            create_file_record(user["id"], source_path.name, str(encrypted_path))
            log_event(user["username"], "ENCRYPT", "SUCCESS", f"Encrypted {source_path.name}.")
            flash(f"File encrypted: {encrypted_path.name}", "success")
            return redirect(url_for("dashboard"))
        except Exception as exc:
            flash(str(exc), "danger")
    return render_template("encrypt.html", user=user)


@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        file_id = request.form.get("file_id", type=int)
        fingerprint_file = request.files.get("fingerprint")
        try:
            file_record = get_file_for_user(file_id, user["id"]) if file_id is not None else None
            if file_record is None:
                log_event(user["username"], "DECRYPT", "FAILED", "Unauthorized encrypted file selection.")
                raise ValueError(ACCESS_DENIED_MESSAGE)
            vault_path = Path(file_record["encrypted_path"])
            fingerprint_path = save_upload(fingerprint_file, UPLOAD_DIR, IMAGE_EXTENSIONS, image_only=True)
            matched, _ = verify_any_user_fingerprint(user, fingerprint_path)
            if not matched:
                log_event(user["username"], "DECRYPT", "FAILED", "Fingerprint mismatch.")
                raise ValueError(FINGERPRINT_DENIED_MESSAGE)
            decrypted_path = decrypt_file(vault_path, user["username"], user["fingerprint_hash"])
            log_event(user["username"], "DECRYPT", "SUCCESS", f"Decrypted {vault_path.name}.")
            flash(f"File decrypted: {decrypted_path.name}", "success")
            return redirect(url_for("dashboard"))
        except Exception as exc:
            flash(str(exc), "danger")
    return render_template("decrypt.html", user=user, files=list_files(user["id"]))


@app.route("/logs")
def logs():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    return render_template("logs.html", user=user, logs=list_logs())


@app.route("/attack", methods=["GET", "POST"])
def attack():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        fingerprint_file = request.files.get("fingerprint")
        try:
            uploaded_path = save_upload(fingerprint_file, UPLOAD_DIR, IMAGE_EXTENSIONS, image_only=True)
            user = get_user(username)
            if user is None:
                log_event(username or None, "ATTACK_SIMULATION", "FAILED", "Unknown username.")
                raise ValueError(ACCESS_DENIED_MESSAGE)
            if is_blocked(user):
                raise ValueError(ACCESS_DENIED_MESSAGE)
            matched, _ = verify_any_user_fingerprint(user, uploaded_path)
            if matched:
                reset_failed_attempts(username)
                log_event(username, "ATTACK_SIMULATION", "SUCCESS", "Correct fingerprint used.")
                flash("Correct fingerprint. Failed attempts reset.", "success")
            else:
                attempts = increment_failed_attempts(username)
                if should_block(attempts):
                    block_user(username)
                    log_event(username, "ATTACK_SIMULATION", "BLOCKED", "User blocked after 3 failures.")
                    flash(ACCESS_DENIED_MESSAGE, "danger")
                else:
                    log_event(username, "ATTACK_SIMULATION", "FAILED", f"Failed attempt {attempts}/3.")
                    flash(ACCESS_DENIED_MESSAGE, "danger")
        except Exception as exc:
            flash(str(exc), "danger")
    return render_template("attack.html")


if __name__ == "__main__":
    bootstrap()
    app.run(debug=False, host="127.0.0.1", port=5001)
