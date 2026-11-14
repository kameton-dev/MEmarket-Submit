import json
import hashlib
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
import zipfile
from functools import wraps

import yaml
from flask import Blueprint, Response, flash, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.utils import secure_filename

from config import ADMIN_PASSWORD, ADMIN_USER, PENDING_DIR, REPO_PATH
from database import get_connection
from security import valid_csrf_token
from versioning import (
    find_published_package,
    prune_published_packages,
    read_package_identity,
    unique_package_name,
    version_is_newer,
)


admin_bp = Blueprint("admin", __name__)
_APP_ID_PATTERN = re.compile(r"^(?!\.{1,2}$)[A-Za-z0-9._-]{1,128}$")


def _pending_directory(submission):
    if not _APP_ID_PATTERN.fullmatch(submission["app_id"]):
        raise ValueError("Некорректный идентификатор приложения")
    storage_key = submission["storage_key"] or submission["app_id"]
    parts = storage_key.replace("\\", "/").split("/")
    if (
        not parts
        or parts[0] != submission["app_id"]
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError("Некорректный путь к файлам заявки")
    return os.path.join(PENDING_DIR, *parts)


def requires_auth(view):
    @wraps(view)
    def decorated(*args, **kwargs):
        if not ADMIN_USER or not ADMIN_PASSWORD:
            return Response("Админ-доступ не настроен.", 503)

        auth = request.authorization
        if not auth or not (
            auth.username == ADMIN_USER and auth.password == ADMIN_PASSWORD
        ):
            return Response(
                "Авторизация требуется.",
                401,
                {"WWW-Authenticate": 'Basic realm="Admin"'},
            )
        return view(*args, **kwargs)

    return decorated


def requires_moderation_access(view):
    """Allow the admin or an approved moderator to handle app submissions."""
    @wraps(view)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if ADMIN_USER and ADMIN_PASSWORD and auth and auth.username == ADMIN_USER and auth.password == ADMIN_PASSWORD:
            return view(*args, **kwargs)
        moderator_id = session.get("moderator_id")
        if not moderator_id:
            return redirect(url_for("moderator.login"))
        conn = get_connection()
        active = conn.execute(
            "SELECT 1 FROM moderators WHERE id = ? AND status = 'active'", (moderator_id,)
        ).fetchone()
        conn.close()
        if not active:
            session.pop("moderator_id", None)
            return redirect(url_for("moderator.login"))
        if request.method == "POST" and not valid_csrf_token(request.form.get("csrf_token")):
            return "Form expired. Refresh the page and try again.", 400
        return view(*args, **kwargs)
    return decorated


def moderation_redirect():
    if session.get("moderator_id"):
        return redirect(url_for("moderator.dashboard"))
    return redirect(url_for("admin.admin_panel"))


@admin_bp.route("/admin")
@requires_auth
def admin_panel():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, app_id, name, developer, category, temp_icon_name, temp_app_name, "
        "storage_key, submission_type, package_version "
        "FROM submissions WHERE status = 'pending'"
    )
    submissions = cursor.fetchall()
    conn.row_factory = sqlite3.Row
    claims = conn.execute(
        """
        SELECT claims.id, claims.app_id, claims.proof, claims.created_at,
               developers.publisher_name, developers.email,
               owners.publisher_name AS current_owner
        FROM claim_requests AS claims
        JOIN developers ON developers.id = claims.developer_id
        LEFT JOIN developer_apps AS apps ON apps.app_id = claims.app_id
        LEFT JOIN developers AS owners ON owners.id = apps.developer_id
        WHERE claims.status = 'pending'
        ORDER BY claims.created_at
        """
    ).fetchall()
    developer_accounts = conn.execute(
        """
        SELECT developers.id, developers.email, developers.publisher_name,
               developers.created_at, COUNT(developer_apps.app_id) AS app_count
        FROM developers
        LEFT JOIN developer_apps ON developer_apps.developer_id = developers.id
        GROUP BY developers.id
        ORDER BY developers.created_at DESC
        """
    ).fetchall()
    moderators = conn.execute(
        "SELECT id, email, status, created_at FROM moderators ORDER BY created_at DESC"
    ).fetchall()
    pending_moderators = conn.execute(
        "SELECT id, email, created_at FROM moderators WHERE status = 'pending' ORDER BY created_at"
    ).fetchall()
    invitations = conn.execute(
        "SELECT id, expires_at, created_at FROM moderator_invitations "
        "WHERE used_at IS NULL AND expires_at > CURRENT_TIMESTAMP ORDER BY created_at DESC"
    ).fetchall()
    conn.close()
    return render_template(
        "admin.html",
        submissions=submissions,
        claims=claims,
        developer_accounts=developer_accounts,
        moderators=moderators,
        pending_moderators=pending_moderators,
        invitations=invitations,
    )


@admin_bp.route("/admin/moderators/invitations", methods=["POST"])
@requires_auth
def create_moderator_invitation():
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "Form expired. Refresh the page and try again.", 400
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = get_connection()
    conn.execute(
        "INSERT INTO moderator_invitations (token_hash, expires_at) "
        "VALUES (?, datetime('now', '+7 days'))",
        (token_hash,),
    )
    conn.commit()
    conn.close()
    invitation_url = url_for("moderator.register", token=token, _external=True)
    return render_template("admin.html", invitation_url=invitation_url, **_admin_page_context())


def _admin_page_context():
    """Build the account and queue data needed after creating an invitation."""
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    submissions = conn.execute(
        "SELECT id, app_id, name, developer, category, temp_icon_name, temp_app_name, "
        "storage_key, submission_type, package_version FROM submissions WHERE status = 'pending'"
    ).fetchall()
    claims = conn.execute(
        "SELECT claims.id, claims.app_id, claims.proof, claims.created_at, developers.publisher_name, "
        "developers.email, owners.publisher_name AS current_owner FROM claim_requests claims "
        "JOIN developers ON developers.id = claims.developer_id "
        "LEFT JOIN developer_apps apps ON apps.app_id = claims.app_id "
        "LEFT JOIN developers owners ON owners.id = apps.developer_id WHERE claims.status = 'pending' "
        "ORDER BY claims.created_at"
    ).fetchall()
    developer_accounts = conn.execute(
        "SELECT developers.id, developers.email, developers.publisher_name, developers.created_at, "
        "COUNT(developer_apps.app_id) AS app_count FROM developers LEFT JOIN developer_apps "
        "ON developer_apps.developer_id = developers.id GROUP BY developers.id ORDER BY developers.created_at DESC"
    ).fetchall()
    moderators = conn.execute("SELECT id, email, status, created_at FROM moderators ORDER BY created_at DESC").fetchall()
    pending_moderators = conn.execute("SELECT id, email, created_at FROM moderators WHERE status='pending' ORDER BY created_at").fetchall()
    invitations = conn.execute("SELECT id, expires_at, created_at FROM moderator_invitations WHERE used_at IS NULL AND expires_at > CURRENT_TIMESTAMP ORDER BY created_at DESC").fetchall()
    conn.close()
    return dict(submissions=submissions, claims=claims, developer_accounts=developer_accounts,
                moderators=moderators, pending_moderators=pending_moderators, invitations=invitations)


@admin_bp.route("/admin/moderators/<int:moderator_id>/approve", methods=["POST"])
@requires_auth
def approve_moderator(moderator_id):
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "Form expired. Refresh the page and try again.", 400
    conn = get_connection()
    cursor = conn.execute(
        "UPDATE moderators SET status='active', approved_at=CURRENT_TIMESTAMP "
        "WHERE id=? AND status='pending'", (moderator_id,)
    )
    conn.commit()
    conn.close()
    flash("Аккаунт модератора одобрен." if cursor.rowcount else "Заявка уже обработана.", "success")
    return redirect(url_for("admin.admin_panel", _anchor="admin-requests-panel"))


@admin_bp.route("/admin/moderators/<int:moderator_id>/reject", methods=["POST"])
@requires_auth
def reject_moderator(moderator_id):
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "Form expired. Refresh the page and try again.", 400
    conn = get_connection()
    cursor = conn.execute("DELETE FROM moderators WHERE id=? AND status='pending'", (moderator_id,))
    conn.commit()
    conn.close()
    flash("Заявка отклонена." if cursor.rowcount else "Заявка уже обработана.", "success")
    return redirect(url_for("admin.admin_panel", _anchor="admin-requests-panel"))


@admin_bp.route("/admin/moderators/<int:moderator_id>/delete", methods=["POST"])
@requires_auth
def delete_moderator(moderator_id):
    if not valid_csrf_token(request.form.get("csrf_token")):
        return "Form expired. Refresh the page and try again.", 400
    conn = get_connection()
    cursor = conn.execute("DELETE FROM moderators WHERE id=?", (moderator_id,))
    conn.commit()
    conn.close()
    flash("Аккаунт модератора удалён." if cursor.rowcount else "Аккаунт не найден.", "success")
    return redirect(url_for("admin.admin_panel", _anchor="admin-accounts-panel"))


@admin_bp.route("/admin/preview/<int:sub_id>")
@requires_moderation_access
def preview_submission(sub_id):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM submissions WHERE id = ? AND status = 'pending'",
        (sub_id,),
    )
    submission = cursor.fetchone()
    conn.close()
    if not submission:
        return jsonify({"error": "Заявка не найдена или уже обработана"}), 404

    try:
        manifest_info = json.loads(submission["manifest_info"] or "{}")
    except json.JSONDecodeError:
        manifest_info = {}
    try:
        screenshot_names = json.loads(submission["screenshot_names"] or "[]")
    except json.JSONDecodeError:
        screenshot_names = []

    return render_template(
        "preview.html",
        submission=submission,
        manifest_info=manifest_info,
        screenshot_names=screenshot_names,
    )


@admin_bp.route("/admin/download-package/<int:sub_id>")
@requires_moderation_access
def download_pending_package(sub_id):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    submission = conn.execute(
        "SELECT * FROM submissions WHERE id = ? AND status = 'pending'",
        (sub_id,),
    ).fetchone()
    conn.close()
    if not submission:
        return jsonify({"error": "Заявка не найдена или уже обработана"}), 404

    try:
        package_dir = _pending_directory(submission)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    package_path = os.path.join(package_dir, submission["temp_app_name"])
    if not os.path.isfile(package_path):
        return jsonify({"error": "Файл пакета не найден"}), 404
    return send_from_directory(
        package_dir,
        submission["temp_app_name"],
        as_attachment=True,
    )


@admin_bp.route("/admin/edit/<int:sub_id>", methods=["GET", "POST"])
@requires_auth
def edit_submission(sub_id):
    categories = [
        ("games", "Игры"),
        ("store", "Магазины приложений"),
        ("entertainment", "Развлечения"),
        ("music+video", "Музыка + видео"),
        ("tools", "Инструменты"),
        ("livestyle", "Лайфстайл"),
        ("news+weather", "Новости + погода"),
        ("photo", "Фото"),
        ("social", "Социальные сети"),
        ("sports", "Спорт"),
        ("business", "Бизнес"),
        ("education", "Обучение"),
        ("other", "Другое"),
    ]

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM submissions WHERE id = ? AND status = 'pending'",
        (sub_id,),
    )
    submission = cursor.fetchone()
    if not submission:
        conn.close()
        return jsonify({"error": "Заявка не найдена или уже обработана"}), 404

    if request.method == "POST":
        if not valid_csrf_token(request.form.get("csrf_token")):
            conn.close()
            return "Form expired. Refresh the page and try again.", 400
        icon = request.files.get("icon_file")
        icon_filename = None
        if icon and icon.filename:
            safe_name = secure_filename(icon.filename)
            icon_data = icon.stream.read(8 * 1024 * 1024 + 1)
            if (
                not safe_name.lower().endswith(".png")
                or len(icon_data) > 8 * 1024 * 1024
                or not icon_data.startswith(b"\x89PNG\r\n\x1a\n")
            ):
                conn.close()
                return render_template(
                    "edit.html", submission=submission, categories=categories,
                    icon_error="Иконка должна быть PNG-файлом размером не больше 8 МБ.",
                ), 400
            package_dir = _pending_directory(submission)
            icon_filename = "icon.png"
            os.makedirs(package_dir, exist_ok=True)
            with open(os.path.join(package_dir, icon_filename), "wb") as icon_file:
                icon_file.write(icon_data)
        cursor.execute(
            """
            UPDATE submissions SET
                name = ?, developer = ?, category = ?,
                summary_type = ?, summary_static = ?, summary_ru = ?, summary_en = ?,
                desc_type = ?, desc_static = ?, desc_ru = ?, desc_en = ?,
                temp_icon_name = COALESCE(?, temp_icon_name)
            WHERE id = ? AND status = 'pending'
            """,
            (
                request.form.get("name", "").strip(),
                request.form.get("developer", "").strip(),
                request.form.get("category", "").strip(),
                request.form.get("summary_type", "static"),
                request.form.get("summary_static", "").strip(),
                request.form.get("summary_ru", "").strip(),
                request.form.get("summary_en", "").strip(),
                request.form.get("desc_type", "static"),
                request.form.get("desc_static", "").strip(),
                request.form.get("desc_ru", "").strip(),
                request.form.get("desc_en", "").strip(),
                icon_filename,
                sub_id,
            ),
        )
        conn.commit()
        conn.close()
        return moderation_redirect()

    conn.close()
    return render_template("edit.html", submission=submission, categories=categories)


@admin_bp.route("/admin/approve/<int:sub_id>", methods=["POST"])
@requires_moderation_access
def approve_submission(sub_id):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM submissions WHERE id = ?", (sub_id,))
    sub = cursor.fetchone()
    if not sub:
        conn.close()
        return jsonify({"error": "Заявка не найдена"}), 404

    app_id = sub["app_id"]
    if not _APP_ID_PATTERN.fullmatch(app_id):
        conn.close()
        return jsonify({"error": "Некорректный идентификатор приложения."}), 400
    app_dir = os.path.join(REPO_PATH, "metadata", app_id)
    try:
        app_pending_dir = _pending_directory(sub)
    except ValueError as error:
        conn.close()
        return jsonify({"error": str(error)}), 400

    try:
        owner = conn.execute(
            "SELECT developer_id, package_name FROM developer_apps WHERE app_id = ?",
            (app_id,),
        ).fetchone()
        published_package_name = sub["temp_app_name"]
        if sub["submission_type"] == "new" and (
            owner or os.path.isfile(os.path.join(app_dir, "metadata.yaml"))
        ):
            conn.close()
            return jsonify(
                {"error": "Приложение уже опубликовано или закреплено. Обновите его либо подтвердите авторство."}
            ), 409
        if sub["submission_type"] == "update":
            if (
                not sub["developer_id"]
                or not owner
                or owner["developer_id"] != sub["developer_id"]
            ):
                conn.close()
                return jsonify({"error": "У разработчика больше нет прав на это приложение."}), 409
            package_path = os.path.join(app_pending_dir, sub["temp_app_name"])
            identity = read_package_identity(package_path)
            published = find_published_package(app_dir, app_id)
            if not published:
                conn.close()
                return jsonify({"error": "Не найден текущий опубликованный пакет для сравнения версии."}), 409
            current_version = published[1]
            if identity["app_id"] != app_id or not version_is_newer(
                identity.get("version"),
                current_version,
            ):
                conn.close()
                return jsonify(
                    {"error": "Версия обновления должна быть строго выше текущей опубликованной версии."}
                ), 409
            published_package_name = unique_package_name(
                app_dir,
                sub["temp_app_name"],
                identity["version"],
            )
        elif (
            sub["developer_id"]
            and owner
            and owner["developer_id"] != sub["developer_id"]
        ):
            conn.close()
            return jsonify({"error": "Приложение уже закреплено за другим разработчиком."}), 409
        os.makedirs(app_dir, exist_ok=True)

        shutil.copy(
            os.path.join(app_pending_dir, sub["temp_app_name"]),
            os.path.join(app_dir, published_package_name),
        )
        if sub["submission_type"] == "update":
            prune_published_packages(app_dir, app_id)
            update_icon_name = os.path.basename(sub["temp_icon_name"] or "")
            update_icon_path = os.path.join(app_pending_dir, update_icon_name)
            if update_icon_name and os.path.isfile(update_icon_path):
                shutil.copy(update_icon_path, os.path.join(app_dir, update_icon_name))
        if sub["submission_type"] != "update":
            shutil.copy(
                os.path.join(app_pending_dir, sub["temp_icon_name"]),
                os.path.join(app_dir, sub["temp_icon_name"]),
            )

            if sub["temp_banner_name"]:
                shutil.copy(
                    os.path.join(app_pending_dir, sub["temp_banner_name"]),
                    os.path.join(app_dir, sub["temp_banner_name"]),
                )

            screenshot_names = json.loads(sub["screenshot_names"] or "[]")
            if screenshot_names:
                screenshots_dir = os.path.join(app_dir, "screenshots")
                os.makedirs(screenshots_dir, exist_ok=True)
                for screenshot_name in screenshot_names:
                    shutil.copy(
                        os.path.join(app_pending_dir, "screenshots", screenshot_name),
                        os.path.join(screenshots_dir, screenshot_name),
                    )

        if sub["desc_type"] == "static":
            with open(os.path.join(app_dir, "description.md"), "w", encoding="utf-8") as file:
                file.write(sub["desc_static"] or "")
        else:
            with open(os.path.join(app_dir, "description_ru.md"), "w", encoding="utf-8") as file:
                file.write(sub["desc_ru"] or "")
            with open(os.path.join(app_dir, "description_en.md"), "w", encoding="utf-8") as file:
                file.write(sub["desc_en"] or "")

        metadata = {
            "title": sub["name"],
            "creator": sub["developer"],
            "category": sub["category"],
        }
        if sub["summary_type"] == "static":
            metadata["summary"] = sub["summary_static"] or ""
        else:
            metadata["summary"] = {
                "ru": sub["summary_ru"] or "",
                "en": sub["summary_en"] or "",
            }

        with open(os.path.join(app_dir, "metadata.yaml"), "w", encoding="utf-8") as file:
            yaml.dump(
                metadata,
                file,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )

        subprocess.run(["memarketrepo", "update", REPO_PATH], check=True)

        if sub["developer_id"]:
            conn.execute(
                """
                INSERT INTO developer_apps (app_id, developer_id, version, package_name)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(app_id) DO UPDATE SET
                    developer_id = excluded.developer_id,
                    version = excluded.version,
                    package_name = excluded.package_name,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (
                    app_id,
                    sub["developer_id"],
                    sub["package_version"],
                    published_package_name,
                ),
            )
        if os.path.exists(app_pending_dir):
            shutil.rmtree(app_pending_dir)
        cursor.execute(
            "UPDATE submissions SET status = 'approved' WHERE id = ?",
            (sub_id,),
        )
        conn.commit()
        conn.close()
        return moderation_redirect()
    except Exception as error:
        conn.close()
        return jsonify({"error": f"Ошибка сборки/публикации: {str(error)}"}), 500


@admin_bp.route("/admin/reject/<int:sub_id>", methods=["POST"])
@requires_moderation_access
def reject_submission(sub_id):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    submission = conn.execute(
        "SELECT * FROM submissions WHERE id = ?",
        (sub_id,),
    ).fetchone()
    cursor = conn.cursor()
    if submission:
        try:
            app_pending_dir = _pending_directory(submission)
        except ValueError as error:
            conn.close()
            return jsonify({"error": str(error)}), 400
        if os.path.exists(app_pending_dir):
            shutil.rmtree(app_pending_dir)
        cursor.execute(
            "UPDATE submissions SET status = 'rejected' WHERE id = ?",
            (sub_id,),
        )
        conn.commit()
    conn.close()
    return moderation_redirect()


@admin_bp.route("/pending_uploads/<path:filepath>")
@requires_moderation_access
def serve_pending_files(filepath):
    return send_from_directory(PENDING_DIR, filepath)


@admin_bp.route("/admin/claims/<int:claim_id>/approve", methods=["POST"])
@requires_auth
def approve_claim(claim_id):
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    claim = conn.execute(
        """
        SELECT id, app_id, developer_id
        FROM claim_requests
        WHERE id = ? AND status = 'pending'
        """,
        (claim_id,),
    ).fetchone()
    if not claim:
        conn.close()
        return jsonify({"error": "Запрос не найден или уже обработан."}), 404

    app_dir = os.path.join(REPO_PATH, "metadata", claim["app_id"])
    published = find_published_package(app_dir, claim["app_id"])
    if not published:
        conn.close()
        return jsonify({"error": "Не найден опубликованный пакет приложения."}), 409

    package_path, package_version = published
    try:
        with open(os.path.join(app_dir, "metadata.yaml"), encoding="utf-8") as file:
            metadata = yaml.safe_load(file) or {}
    except (OSError, yaml.YAMLError) as error:
        conn.close()
        return jsonify({"error": f"Не удалось прочитать metadata.yaml: {error}"}), 500
    if not isinstance(metadata, dict):
        conn.close()
        return jsonify({"error": "metadata.yaml должен содержать объект приложения."}), 409

    summary = metadata.get("summary", "")
    summary_type = "multilingual" if isinstance(summary, dict) else "static"
    if summary_type == "multilingual":
        summary_static = None
        summary_ru = summary.get("ru", "")
        summary_en = summary.get("en", "")
    else:
        summary_static = summary or ""
        summary_ru = summary_en = None

    def read_text(filename):
        try:
            with open(os.path.join(app_dir, filename), encoding="utf-8") as file:
                return file.read()
        except FileNotFoundError:
            return ""

    has_localized_descriptions = any(
        os.path.isfile(os.path.join(app_dir, filename))
        for filename in ("description_ru.md", "description_en.md")
    )
    if has_localized_descriptions:
        desc_type = "multilingual"
        desc_static = None
        desc_ru = read_text("description_ru.md")
        desc_en = read_text("description_en.md")
    else:
        desc_type = "static"
        desc_static = read_text("description.md")
        desc_ru = desc_en = None

    screenshots_dir = os.path.join(app_dir, "screenshots")
    screenshot_names = (
        sorted(
            filename
            for filename in os.listdir(screenshots_dir)
            if os.path.isfile(os.path.join(screenshots_dir, filename))
        )
        if os.path.isdir(screenshots_dir)
        else []
    )
    icon_name = "icon.png"
    if not os.path.isfile(os.path.join(app_dir, icon_name)):
        icon_name = next(
            (
                filename
                for filename in os.listdir(app_dir)
                if filename.lower().startswith("icon.")
                and os.path.isfile(os.path.join(app_dir, filename))
            ),
            "",
        )
    banner_name = next(
        (
            filename
            for filename in os.listdir(app_dir)
            if filename.startswith("banner")
            and os.path.isfile(os.path.join(app_dir, filename))
        ),
        None,
    )
    try:
        identity = read_package_identity(package_path)
    except (OSError, ValueError, zipfile.BadZipFile, ET.ParseError) as error:
        conn.close()
        return jsonify({"error": f"Не удалось прочитать опубликованный пакет: {error}"}), 409
    conn.execute(
        """
        INSERT INTO submissions (
            app_id, name, temp_app_name, temp_icon_name, developer, category,
            summary_type, summary_static, summary_ru, summary_en,
            desc_type, desc_static, desc_ru, desc_en, manifest_info,
            temp_banner_name, screenshot_names, developer_id, submission_type,
            package_version, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, 'approved')
        """,
        (
            claim["app_id"],
            metadata.get("title") or claim["app_id"],
            package_path.name,
            icon_name,
            metadata.get("creator") or "",
            metadata.get("category") or "other",
            summary_type,
            summary_static,
            summary_ru,
            summary_en,
            desc_type,
            desc_static,
            desc_ru,
            desc_en,
            json.dumps(identity, ensure_ascii=False),
            banner_name,
            json.dumps(screenshot_names, ensure_ascii=False),
            claim["developer_id"],
            package_version,
        ),
    )
    conn.execute(
        """
        INSERT INTO developer_apps (app_id, developer_id, version, package_name)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(app_id) DO UPDATE SET
            developer_id = excluded.developer_id,
            version = excluded.version,
            package_name = excluded.package_name,
            updated_at = CURRENT_TIMESTAMP
        """,
        (claim["app_id"], claim["developer_id"], package_version, package_path.name),
    )
    conn.execute(
        "UPDATE claim_requests SET status = 'approved' WHERE id = ?",
        (claim_id,),
    )
    conn.execute(
        "UPDATE claim_requests SET status = 'rejected' "
        "WHERE app_id = ? AND id != ? AND status = 'pending'",
        (claim["app_id"], claim_id),
    )
    conn.commit()
    conn.close()
    return redirect(url_for("admin.admin_panel"))


@admin_bp.route("/admin/claims/<int:claim_id>/reject", methods=["POST"])
@requires_auth
def reject_claim(claim_id):
    conn = get_connection()
    cursor = conn.execute(
        "UPDATE claim_requests SET status = 'rejected' "
        "WHERE id = ? AND status = 'pending'",
        (claim_id,),
    )
    conn.commit()
    conn.close()
    if not cursor.rowcount:
        return jsonify({"error": "Запрос не найден или уже обработан."}), 404
    return redirect(url_for("admin.admin_panel"))
