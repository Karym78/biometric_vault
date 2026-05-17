from pathlib import Path
from uuid import uuid4

from flask import Flask, flash, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.utils import secure_filename
from PIL import Image

from modules.attack_detector import is_blocked, should_block
from modules.biometric import fingerprint_hash
from modules.biometric_preprocessing import save_preprocessed_preview
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
    list_all_files,
    list_files,
    list_logs,
    list_user_fingerprints,
    list_users_for_attack_demo,
    reset_failed_attempts,
)
from modules.logger import log_event
from modules.matching_score import SECURITY_LEVELS, compare_fingerprint_images, threshold_for_level
from modules.paths import FINGERPRINT_DIR, UPLOAD_DIR, WATERMARKED_DIR, ensure_directories
from modules.performance_metrics import security_level_rows
from modules.watermark import embed_watermark, extract_watermark, validate_watermark
from modules.watermark_attacks import ATTACKS
from modules.watermark_metrics import bit_error_rate, calculate_psnr, message_bits, normalized_correlation


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


def current_security_level() -> str:
    return session.get("security_level", "medium")


def current_threshold() -> float:
    return threshold_for_level(current_security_level())


def file_url(path: str | Path) -> str:
    path = Path(path)
    if path.parent == WATERMARKED_DIR:
        return url_for("watermarked_file", filename=path.name)
    return url_for("static", filename=f"uploads/{path.name}")


def find_user_fingerprint(user_id: int, fingerprint_id: int | None) -> dict | None:
    for fingerprint in list_user_fingerprints(user_id):
        if fingerprint["id"] == fingerprint_id:
            return fingerprint
    return None


def selected_fingerprint_from_form(user: dict) -> dict:
    fingerprint_id = request.form.get("fingerprint_id", type=int)
    fingerprint = find_user_fingerprint(user["id"], fingerprint_id)
    if fingerprint is None:
        raise ValueError("Select a registered fingerprint.")
    return fingerprint


def expected_watermark_message(user: dict, fingerprint: dict | None = None, label: str | None = None) -> str:
    if label is not None:
        return f"OWNER:{user['username']}|LABEL:{label}|PROJECT:BIOMETRIC_VAULT"
    if fingerprint and fingerprint.get("is_primary"):
        return f"OWNER:{user['username']}|TYPE:PRIMARY|PROJECT:BIOMETRIC_VAULT"
    if fingerprint:
        return f"OWNER:{user['username']}|LABEL:{fingerprint.get('label') or 'Additional fingerprint'}|PROJECT:BIOMETRIC_VAULT"
    return f"OWNER:{user['username']}|TYPE:PRIMARY|PROJECT:BIOMETRIC_VAULT"


def verify_any_user_fingerprint(user: dict, uploaded_path: Path) -> tuple[bool, str | None, dict | None]:
    fingerprints = list_user_fingerprints(user["id"])
    best_result = None
    for fingerprint in fingerprints:
        result = compare_fingerprint_images(
            fingerprint["watermarked_image_path"],
            uploaded_path,
            current_threshold(),
        )
        result["label"] = fingerprint["label"] or "Fingerprint"
        if best_result is None or result["score"] > best_result["score"]:
            best_result = result
    if best_result and best_result["decision"]:
        return True, fingerprint_hash(uploaded_path), best_result
    return False, None, best_result


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
            if request.form.get("consent") != "on":
                raise ValueError("Biometric data processing consent is required.")
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
            watermarked_path = embed_watermark(saved_path, f"OWNER:{username}|TYPE:PRIMARY|PROJECT:BIOMETRIC_VAULT")
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
            matched, _, match_result = verify_any_user_fingerprint(user, uploaded_path)
            if not matched:
                attempts = increment_failed_attempts(username)
                score = match_result["score"] if match_result else 0
                log_message = f"Wrong fingerprint. Score {score}, threshold {current_threshold()}. Failed attempts: {attempts}/3."
                status = "FAILED"
                if should_block(attempts):
                    block_user(username)
                    status = "BLOCKED"
                    log_message = "User blocked after 3 wrong fingerprint attempts."
                log_event(username, "LOGIN", status, log_message)
                raise ValueError(ACCESS_DENIED_MESSAGE)
            reset_failed_attempts(username)
            session["user_id"] = user["id"]
            flash(
                f"Access granted. Score {match_result['score']} / threshold {match_result['threshold']}.",
                "success",
            )
            log_event(username, "LOGIN", "SUCCESS", f"Fingerprint matched with score {match_result['score']}.")
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
        security_level=current_security_level(),
        threshold=current_threshold(),
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
            watermarked_path = embed_watermark(saved_path, expected_watermark_message(user, label=label))
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
            matched, _, match_result = verify_any_user_fingerprint(user, fingerprint_path)
            if not matched:
                score = match_result["score"] if match_result else 0
                log_event(user["username"], "ENCRYPT", "FAILED", f"Fingerprint mismatch. Score {score}.")
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
            matched, _, match_result = verify_any_user_fingerprint(user, fingerprint_path)
            if not matched:
                score = match_result["score"] if match_result else 0
                log_event(user["username"], "DECRYPT", "FAILED", f"Fingerprint mismatch. Score {score}.")
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


@app.route("/data/watermarked/<path:filename>")
def watermarked_file(filename: str):
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    fingerprints = list_user_fingerprints(user["id"])
    if not any(Path(fingerprint["watermarked_image_path"]).name == filename for fingerprint in fingerprints):
        flash(ACCESS_DENIED_MESSAGE, "danger")
        return redirect(url_for("dashboard"))
    return send_from_directory(WATERMARKED_DIR, filename)


@app.route("/biometric-analysis", methods=["GET", "POST"])
def biometric_analysis():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    result = None
    original_url = None
    preprocessed_url = None
    if request.method == "POST":
        fingerprint_file = request.files.get("fingerprint")
        try:
            uploaded_path = save_upload(fingerprint_file, UPLOAD_DIR, IMAGE_EXTENSIONS, image_only=True)
            preprocessed_path = save_preprocessed_preview(uploaded_path)
            matched, _, result = verify_any_user_fingerprint(user, uploaded_path)
            original_url = file_url(uploaded_path)
            preprocessed_url = file_url(preprocessed_path)
            log_event(
                user["username"],
                "BIOMETRIC_ANALYSIS",
                "SUCCESS" if matched else "FAILED",
                f"Score {result['score'] if result else 0}, threshold {current_threshold()}.",
            )
        except Exception as exc:
            flash(str(exc), "danger")
    return render_template(
        "biometric_analysis.html",
        user=user,
        result=result,
        original_url=original_url,
        preprocessed_url=preprocessed_url,
        threshold=current_threshold(),
    )


@app.route("/performance", methods=["GET", "POST"])
def performance():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    if request.method == "POST":
        level = request.form.get("security_level", "medium")
        if level not in SECURITY_LEVELS:
            flash("Invalid security level.", "danger")
        else:
            session["security_level"] = level
            flash(f"Security level set to {level}.", "success")
    return render_template(
        "performance.html",
        user=user,
        rows=security_level_rows(),
        security_level=current_security_level(),
        threshold=current_threshold(),
    )


@app.route("/watermark", methods=["GET", "POST"])
def watermark():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    fingerprints = list_user_fingerprints(user["id"])
    selected = None
    message = None
    valid = None
    if request.method == "POST":
        try:
            selected = selected_fingerprint_from_form(user)
            valid, message = validate_watermark(selected["watermarked_image_path"], user["username"])
            log_event(user["username"], "WATERMARK", "SUCCESS" if valid else "FAILED", "Watermark extracted.")
        except Exception as exc:
            valid = False
            message = str(exc)
            log_event(user["username"], "WATERMARK", "FAILED", str(exc))
    return render_template(
        "watermark.html",
        user=user,
        fingerprints=fingerprints,
        selected=selected,
        message=message,
        valid=valid,
        image_url=file_url(selected["watermarked_image_path"]) if selected else None,
    )


@app.route("/watermark-evaluation", methods=["GET", "POST"])
def watermark_evaluation():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    fingerprints = list_user_fingerprints(user["id"])
    selected = None
    metrics = None
    if request.method == "POST":
        original_file = request.files.get("original")
        try:
            selected = selected_fingerprint_from_form(user)
            original_path = save_upload(original_file, UPLOAD_DIR, IMAGE_EXTENSIONS, image_only=True)
            watermarked_path = selected["watermarked_image_path"]
            extracted = extract_watermark(watermarked_path)
            expected = expected_watermark_message(user, selected)
            metrics = {
                "psnr": calculate_psnr(original_path, watermarked_path),
                "ber": bit_error_rate(expected, extracted),
                "nc": normalized_correlation(expected, extracted),
                "payload": len(message_bits(extracted)),
                "message": extracted,
            }
            log_event(user["username"], "WATERMARK_EVALUATION", "SUCCESS", "Watermark metrics calculated.")
        except Exception as exc:
            flash(str(exc), "danger")
            log_event(user["username"], "WATERMARK_EVALUATION", "FAILED", str(exc))
    return render_template(
        "watermark_evaluation.html",
        user=user,
        fingerprints=fingerprints,
        selected=selected,
        metrics=metrics,
        image_url=file_url(selected["watermarked_image_path"]) if selected else None,
    )


@app.route("/watermark-attacks", methods=["GET", "POST"])
def watermark_attacks():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    fingerprints = list_user_fingerprints(user["id"])
    selected = None
    result = None
    if request.method == "POST":
        attack_name = request.form.get("attack_name", "jpeg")
        try:
            selected = selected_fingerprint_from_form(user)
            if attack_name not in ATTACKS:
                raise ValueError("Invalid attack type.")
            original_message = extract_watermark(selected["watermarked_image_path"])
            attacked_path = ATTACKS[attack_name](selected["watermarked_image_path"])
            try:
                attacked_message = extract_watermark(attacked_path)
                valid = user["username"] in attacked_message
            except Exception as exc:
                attacked_message = str(exc)
                valid = False
            result = {
                "attack_name": attack_name,
                "image_url": file_url(attacked_path),
                "valid": valid,
                "message": attacked_message,
                "ber": bit_error_rate(original_message, attacked_message),
                "nc": normalized_correlation(original_message, attacked_message),
            }
            log_event(user["username"], "WATERMARK_ATTACK", "SUCCESS", f"{attack_name} attack simulated.")
        except Exception as exc:
            flash(str(exc), "danger")
            log_event(user["username"], "WATERMARK_ATTACK", "FAILED", str(exc))
    return render_template(
        "watermark_attacks.html",
        user=user,
        fingerprints=fingerprints,
        selected=selected,
        attacks=ATTACKS.keys(),
        result=result,
    )


@app.route("/rgpd")
def rgpd():
    return render_template("rgpd.html")


@app.route("/security-model")
def security_model():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    return render_template("security_model.html", user=user)


@app.route("/database-attack")
def database_attack():
    user = require_login()
    if user is None:
        return redirect(url_for("login"))
    return render_template(
        "database_attack.html",
        user=user,
        users=list_users_for_attack_demo(),
        files=list_all_files(),
        logs=list_logs(20),
    )


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
            matched, _, match_result = verify_any_user_fingerprint(user, uploaded_path)
            if matched:
                reset_failed_attempts(username)
                log_event(username, "ATTACK_SIMULATION", "SUCCESS", f"Correct fingerprint used. Score {match_result['score']}.")
                flash(f"Correct fingerprint. Score {match_result['score']}. Failed attempts reset.", "success")
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
