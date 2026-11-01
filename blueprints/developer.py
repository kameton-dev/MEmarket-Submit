import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import uuid
import xml.etree.ElementTree as ET
import zipfile
from functools import wraps

import yaml
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import PENDING_DIR, REPO_PATH
from database import get_connection
from security import valid_csrf_token
from versioning import (
    find_published_package,
    parse_version,
    read_package_identity,
    version_is_newer,
)

developer_bp = Blueprint("developer", __name__)
_APP_ID_PATTERN = re.compile(r"^(?!\.{1,2}$)[A-Za-z0-9._-]{1,128}$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_APP_CATEGORIES = [
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


@developer_bp.before_request
def protect_post_requests():
    if request.method == "POST" and not valid_csrf_token(
        request.form.get("csrf_token")
    ):
        return "Форма устарела. Обновите страницу и повторите попытку.", 400


def developer_required(view):
    @wraps(view)
    def decorated(*args, **kwargs):
        if not session.get("developer_id"):
            return redirect(url_for("developer.login"))
        return view(*args, **kwargs)

    return decorated


@developer_bp.route("/developer/register", methods=["GET", "POST"])
def register():
    if session.get("developer_id"):
        return redirect(url_for("developer.dashboard"))
    if request.method == "GET":
        return render_template("developer_auth.html", mode="register")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    publisher_name = request.form.get("publisher_name", "").strip()
    if not _EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        flash("Введите корректный email.", "error")
    elif len(password) < 12:
        flash("Пароль должен содержать не менее 12 символов.", "error")
    elif not publisher_name or len(publisher_name) > 80:
        flash("Имя издателя должно содержать от 1 до 80 символов.", "error")
    else:
        conn = get_connection()
        try:
            cursor = conn.execute(
                "INSERT INTO developers (email, password_hash, publisher_name) "
                "VALUES (?, ?, ?)",
                (email, generate_password_hash(password), publisher_name),
            )
            conn.commit()
            developer_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            flash("Этот email или имя издателя уже заняты.", "error")
        else:
            session.clear()
            session["developer_id"] = developer_id
            session["publisher_name"] = publisher_name
            return redirect(url_for("developer.dashboard"))
        finally:
            conn.close()
    return render_template("developer_auth.html", mode="register")


@developer_bp.route("/developer/login", methods=["GET", "POST"])
def login():
    if session.get("developer_id"):
        return redirect(url_for("developer.dashboard"))
    if request.method == "GET":
        return render_template("developer_auth.html", mode="login")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    developer = conn.execute(
        "SELECT id, password_hash, publisher_name FROM developers WHERE email = ?",
        (email,),
    ).fetchone()
    conn.close()
    if not developer or not check_password_hash(developer["password_hash"], password):
        flash("Неверный email или пароль.", "error")
        return render_template("developer_auth.html", mode="login"), 401

    session.clear()
    session["developer_id"] = developer["id"]
    session["publisher_name"] = developer["publisher_name"]
    return redirect(url_for("developer.dashboard"))


@developer_bp.route("/developer/logout", methods=["POST"])
@developer_required
def logout():
    session.clear()
    return redirect(url_for("main.index"))


@developer_bp.route("/developer/account/password", methods=["POST"])
@developer_required
def change_password():
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    conn = get_connection()
    developer = conn.execute(
        "SELECT password_hash FROM developers WHERE id = ?",
        (session["developer_id"],),
    ).fetchone()
    if not developer:
        conn.close()
        session.clear()
        return redirect(url_for("developer.login"))

    if not check_password_hash(developer[0], current_password):
        conn.close()
        flash("Текущий пароль указан неверно.", "error")
    elif len(new_password) < 12:
        conn.close()
        flash("Новый пароль должен содержать не менее 12 символов.", "error")
    elif new_password != confirm_password:
        conn.close()
        flash("Новый пароль и подтверждение не совпадают.", "error")
    elif check_password_hash(developer[0], new_password):
        conn.close()
        flash("Новый пароль должен отличаться от текущего.", "error")
    else:
        conn.execute(
            "UPDATE developers SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), session["developer_id"]),
        )
        conn.commit()
        conn.close()
        flash("Пароль успешно изменён.", "success")
    return redirect(url_for("developer.dashboard"))


@developer_bp.route("/developer/account/delete", methods=["POST"])
@developer_required
def delete_account():
    developer_id = session["developer_id"]
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    developer = conn.execute(
        "SELECT publisher_name FROM developers WHERE id = ?",
        (developer_id,),
    ).fetchone()
    if not developer:
        conn.close()
        session.clear()
        return redirect(url_for("developer.login"))

    if request.form.get("publisher_name", "").strip() != developer["publisher_name"]:
        conn.close()
        flash("Введённый никнейм не совпадает с никнеймом аккаунта.", "error")
        return redirect(url_for("developer.dashboard"))

    delete_apps = request.form.get("delete_apps") == "yes"
    owned_apps = conn.execute(
        "SELECT app_id FROM developer_apps WHERE developer_id = ?",
        (developer_id,),
    ).fetchall()
    pending_submissions = conn.execute(
        "SELECT app_id, storage_key FROM submissions "
        "WHERE developer_id = ? AND status = 'pending'",
        (developer_id,),
    ).fetchall()
    conn.close()

    staged_apps = []
    staging_dir = None
    metadata_root = os.path.realpath(os.path.join(REPO_PATH, "metadata"))
    if delete_apps and owned_apps:
        if not os.path.isdir(REPO_PATH):
            flash("Не удалось удалить приложения: каталог репозитория не найден.", "error")
            return redirect(url_for("developer.dashboard"))
        app_directories = []
        for app in owned_apps:
            app_id = app["app_id"]
            if not _APP_ID_PATTERN.fullmatch(app_id):
                flash(
                    "Удаление остановлено: у аккаунта найден некорректный App ID.",
                    "error",
                )
                return redirect(url_for("developer.dashboard"))
            unresolved_app_dir = os.path.join(metadata_root, app_id)
            if os.path.islink(unresolved_app_dir):
                flash("Удаление остановлено: каталог приложения является ссылкой.", "error")
                return redirect(url_for("developer.dashboard"))
            app_dir = os.path.realpath(unresolved_app_dir)
            if (
                app_dir == metadata_root
                or os.path.commonpath((metadata_root, app_dir)) != metadata_root
            ):
                flash("Удаление остановлено: обнаружен некорректный путь приложения.", "error")
                return redirect(url_for("developer.dashboard"))
            if os.path.isdir(app_dir):
                app_directories.append((app_id, app_dir))

        try:
            if app_directories:
                staging_dir = tempfile.mkdtemp(
                    prefix=".developer-app-delete-",
                    dir=os.path.dirname(os.path.abspath(REPO_PATH)),
                )
                for app_id, app_dir in app_directories:
                    staged_path = os.path.join(staging_dir, app_id)
                    shutil.move(app_dir, staged_path)
                    staged_apps.append((app_id, staged_path))
                subprocess.run(["memarketrepo", "update", REPO_PATH], check=True)
        except (OSError, subprocess.CalledProcessError) as error:
            restore_errors = []
            for app_id, staged_path in staged_apps:
                try:
                    if os.path.exists(staged_path):
                        os.makedirs(metadata_root, exist_ok=True)
                        shutil.move(staged_path, os.path.join(metadata_root, app_id))
                except OSError as restore_error:
                    restore_errors.append(str(restore_error))
            if staging_dir and os.path.isdir(staging_dir):
                try:
                    shutil.rmtree(staging_dir)
                except OSError as cleanup_error:
                    restore_errors.append(f"не удалось очистить временный каталог: {cleanup_error}")
            try:
                subprocess.run(["memarketrepo", "update", REPO_PATH], check=True)
            except (OSError, subprocess.CalledProcessError) as update_error:
                restore_errors.append(f"не удалось восстановить индекс: {update_error}")
            message = f"Не удалось удалить приложения; аккаунт сохранён: {error}"
            if restore_errors:
                message += " Ошибки восстановления: " + "; ".join(restore_errors)
            flash(message, "error")
            return redirect(url_for("developer.dashboard"))

    conn = get_connection()
    try:
        conn.execute("BEGIN")
        conn.execute(
            "DELETE FROM submissions WHERE developer_id = ? AND status = 'pending'",
            (developer_id,),
        )
        conn.execute(
            "UPDATE submissions SET developer_id = NULL WHERE developer_id = ?",
            (developer_id,),
        )
        conn.execute("DELETE FROM developers WHERE id = ?", (developer_id,))
        conn.commit()
    except sqlite3.Error as error:
        conn.rollback()
        restore_errors = []
        for app_id, staged_path in staged_apps:
            try:
                if os.path.exists(staged_path):
                    os.makedirs(metadata_root, exist_ok=True)
                    shutil.move(staged_path, os.path.join(metadata_root, app_id))
            except OSError as restore_error:
                restore_errors.append(str(restore_error))
        if staging_dir and os.path.isdir(staging_dir):
            try:
                shutil.rmtree(staging_dir)
            except OSError as cleanup_error:
                restore_errors.append(f"не удалось очистить временный каталог: {cleanup_error}")
        if staged_apps:
            try:
                subprocess.run(["memarketrepo", "update", REPO_PATH], check=True)
            except (OSError, subprocess.CalledProcessError) as update_error:
                restore_errors.append(f"не удалось восстановить индекс: {update_error}")
        conn.close()
        message = f"Не удалось удалить аккаунт: {error}"
        if restore_errors:
            message += " Ошибки восстановления: " + "; ".join(restore_errors)
        flash(message, "error")
        return redirect(url_for("developer.dashboard"))
    conn.close()

    cleanup_errors = []
    if staging_dir and os.path.isdir(staging_dir):
        try:
            shutil.rmtree(staging_dir)
        except OSError as error:
            cleanup_errors.append(f"не удалось очистить временный каталог: {error}")

    pending_root = os.path.realpath(PENDING_DIR)
    for submission in pending_submissions:
        app_id = submission["app_id"]
        storage_key = (submission["storage_key"] or app_id).replace("\\", "/")
        parts = storage_key.split("/")
        if (
            not _APP_ID_PATTERN.fullmatch(app_id)
            or not parts
            or parts[0] != app_id
            or any(part in {"", ".", ".."} for part in parts)
            or len(parts) < 2
        ):
            continue
        pending_path = os.path.realpath(os.path.join(PENDING_DIR, *parts))
        if os.path.commonpath((pending_root, pending_path)) != pending_root:
            continue
        if os.path.isdir(pending_path):
            try:
                shutil.rmtree(pending_path)
            except OSError as error:
                cleanup_errors.append(str(error))

    session.clear()
    if delete_apps:
        message = "Аккаунт удалён вместе с опубликованными приложениями."
    else:
        message = "Аккаунт удалён. Опубликованные приложения оставлены без владельца."
    if cleanup_errors:
        message += " Не удалось удалить некоторые временные файлы: " + "; ".join(cleanup_errors)
        flash(message, "error")
    else:
        flash(message, "success")
    return redirect(url_for("main.index"))


@developer_bp.route("/developer")
@developer_required
def dashboard():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    developer = conn.execute(
        "SELECT id, email, publisher_name FROM developers WHERE id = ?",
        (session["developer_id"],),
    ).fetchone()
    if not developer:
        conn.close()
        session.clear()
        return redirect(url_for("developer.login"))
    apps = conn.execute(
        """
        SELECT apps.app_id, apps.version, apps.package_name, submissions.name
        FROM developer_apps AS apps
        LEFT JOIN submissions
            ON submissions.app_id = apps.app_id
            AND submissions.submission_type = 'new'
            AND submissions.status = 'approved'
            AND submissions.developer_id = apps.developer_id
        WHERE apps.developer_id = ?
        GROUP BY apps.app_id
        ORDER BY apps.app_id
        """,
        (developer["id"],),
    ).fetchall()
    pending_submissions = conn.execute(
        """
        SELECT id, app_id, name, submission_type, package_version, status
        FROM submissions
        WHERE developer_id = ? AND status = 'pending'
        ORDER BY id DESC
        """,
        (developer["id"],),
    ).fetchall()
    claims = conn.execute(
        "SELECT app_id, status, created_at FROM claim_requests "
        "WHERE developer_id = ? ORDER BY created_at DESC",
        (developer["id"],),
    ).fetchall()
    conn.close()
    return render_template(
        "developer_dashboard.html",
        developer=developer,
        apps=apps,
        pending_submissions=pending_submissions,
        claims=claims,
    )


@developer_bp.route("/developer/apps/<app_id>/edit", methods=["GET", "POST"])
@developer_required
def edit_app(app_id):
    if not _APP_ID_PATTERN.fullmatch(app_id):
        return "Некорректный идентификатор приложения.", 400

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    app = conn.execute(
        """
        SELECT apps.app_id, submissions.name, submissions.developer,
               submissions.category, submissions.summary_type,
               submissions.summary_static, submissions.summary_ru,
               submissions.summary_en, submissions.desc_type,
               submissions.desc_static, submissions.desc_ru, submissions.desc_en
        FROM developer_apps AS apps
        LEFT JOIN submissions
            ON submissions.app_id = apps.app_id
            AND submissions.submission_type = 'new'
            AND submissions.status = 'approved'
            AND submissions.developer_id = apps.developer_id
        WHERE apps.app_id = ? AND apps.developer_id = ?
        ORDER BY submissions.id DESC
        LIMIT 1
        """,
        (app_id, session["developer_id"]),
    ).fetchone()
    conn.close()
    if not app:
        return "Приложение не найдено в вашем аккаунте.", 404

    app_dir = os.path.join(REPO_PATH, "metadata", app_id)
    metadata_path = os.path.join(app_dir, "metadata.yaml")
    if not os.path.isfile(metadata_path):
        return "Метаданные опубликованного приложения не найдены.", 404

    try:
        with open(metadata_path, encoding="utf-8") as file:
            metadata = yaml.safe_load(file) or {}
    except (OSError, yaml.YAMLError) as error:
        return f"Не удалось прочитать metadata.yaml: {error}", 500
    if not isinstance(metadata, dict):
        return "metadata.yaml должен содержать объект приложения.", 409

    summary = metadata.get("summary", "")
    summary_type = "multilingual" if isinstance(summary, dict) else "static"
    if summary_type == "multilingual":
        summary_static = ""
        summary_ru = summary.get("ru", "")
        summary_en = summary.get("en", "")
    else:
        summary_static = summary or ""
        summary_ru = ""
        summary_en = ""

    def read_description(filename):
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
        desc_static = ""
        desc_ru = read_description("description_ru.md")
        desc_en = read_description("description_en.md")
    else:
        desc_type = "static"
        desc_static = read_description("description.md")
        desc_ru = ""
        desc_en = ""

    form_data = {
        "name": metadata.get("title", app["name"] or ""),
        "developer": metadata.get("creator", app["developer"] or ""),
        "category": metadata.get("category", app["category"] or "other"),
        "summary_type": summary_type,
        "summary_static": summary_static,
        "summary_ru": summary_ru,
        "summary_en": summary_en,
        "desc_type": desc_type,
        "desc_static": desc_static,
        "desc_ru": desc_ru,
        "desc_en": desc_en,
    }

    if request.method == "POST":
        form_data.update(
            {
                "name": request.form.get("name", "").strip(),
                "developer": request.form.get("developer", "").strip(),
                "category": request.form.get("category", "").strip(),
                "summary_type": request.form.get("summary_type", ""),
                "summary_static": request.form.get("summary_static", "").strip(),
                "summary_ru": request.form.get("summary_ru", "").strip(),
                "summary_en": request.form.get("summary_en", "").strip(),
                "desc_type": request.form.get("desc_type", ""),
                "desc_static": request.form.get("desc_static", ""),
                "desc_ru": request.form.get("desc_ru", ""),
                "desc_en": request.form.get("desc_en", ""),
            }
        )
        if (
            not form_data["name"]
            or len(form_data["name"]) > 200
            or not form_data["developer"]
            or len(form_data["developer"]) > 200
            or any(
                len(form_data[field]) > 500
                for field in ("summary_static", "summary_ru", "summary_en")
            )
            or any(
                len(form_data[field]) > 20000
                for field in ("desc_static", "desc_ru", "desc_en")
            )
            or form_data["category"] not in {value for value, _ in _APP_CATEGORIES}
            or form_data["summary_type"] not in {"static", "multilingual"}
            or form_data["desc_type"] not in {"static", "multilingual"}
        ):
            flash("Проверьте название, разработчика, категорию и типы описаний.", "error")
            return render_template(
                "developer_app_edit.html",
                app_id=app_id,
                form_data=form_data,
                categories=_APP_CATEGORIES,
            ), 400

        updated_metadata = {
            "title": form_data["name"],
            "creator": form_data["developer"],
            "category": form_data["category"],
        }
        if form_data["summary_type"] == "static":
            updated_metadata["summary"] = form_data["summary_static"]
        else:
            updated_metadata["summary"] = {
                "ru": form_data["summary_ru"],
                "en": form_data["summary_en"],
            }

        try:
            with open(metadata_path, "w", encoding="utf-8") as file:
                yaml.dump(
                    updated_metadata,
                    file,
                    allow_unicode=True,
                    default_flow_style=False,
                    sort_keys=False,
                )
            if form_data["desc_type"] == "static":
                with open(os.path.join(app_dir, "description.md"), "w", encoding="utf-8") as file:
                    file.write(form_data["desc_static"])
                for filename in ("description_ru.md", "description_en.md"):
                    localized_path = os.path.join(app_dir, filename)
                    if os.path.exists(localized_path):
                        os.remove(localized_path)
            else:
                for filename, key in (
                    ("description_ru.md", "desc_ru"),
                    ("description_en.md", "desc_en"),
                ):
                    with open(os.path.join(app_dir, filename), "w", encoding="utf-8") as file:
                        file.write(form_data[key])
                static_path = os.path.join(app_dir, "description.md")
                if os.path.exists(static_path):
                    os.remove(static_path)

            conn = get_connection()
            try:
                conn.execute(
                    """
                    UPDATE submissions SET
                        name = ?, developer = ?, category = ?,
                        summary_type = ?, summary_static = ?, summary_ru = ?, summary_en = ?,
                        desc_type = ?, desc_static = ?, desc_ru = ?, desc_en = ?
                    WHERE app_id = ? AND developer_id = ?
                        AND submission_type = 'new' AND status = 'approved'
                    """,
                    (
                        form_data["name"],
                        form_data["developer"],
                        form_data["category"],
                        form_data["summary_type"],
                        form_data["summary_static"] if form_data["summary_type"] == "static" else None,
                        form_data["summary_ru"] if form_data["summary_type"] == "multilingual" else None,
                        form_data["summary_en"] if form_data["summary_type"] == "multilingual" else None,
                        form_data["desc_type"],
                        form_data["desc_static"] if form_data["desc_type"] == "static" else None,
                        form_data["desc_ru"] if form_data["desc_type"] == "multilingual" else None,
                        form_data["desc_en"] if form_data["desc_type"] == "multilingual" else None,
                        app_id,
                        session["developer_id"],
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        except (OSError, sqlite3.Error, yaml.YAMLError) as error:
            flash(f"Не удалось сохранить данные приложения: {error}", "error")
            return render_template(
                "developer_app_edit.html",
                app_id=app_id,
                form_data=form_data,
                categories=_APP_CATEGORIES,
            ), 500

        try:
            subprocess.run(["memarketrepo", "update", REPO_PATH], check=True)
        except (OSError, subprocess.CalledProcessError) as error:
            flash(
                "Данные карточки сохранены, но memarketrepo не обновил индекс: "
                f"{error}",
                "error",
            )
            return redirect(url_for("developer.edit_app", app_id=app_id))

        flash("Карточка приложения обновлена без модерации.", "success")
        return redirect(url_for("developer.dashboard"))

    return render_template(
        "developer_app_edit.html",
        app_id=app_id,
        form_data=form_data,
        categories=_APP_CATEGORIES,
    )


@developer_bp.route("/developer/apps/<app_id>/update", methods=["GET", "POST"])
@developer_required
def upload_update(app_id):
    if not _APP_ID_PATTERN.fullmatch(app_id):
        return "Некорректный идентификатор приложения.", 400

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    app = conn.execute(
        """
        SELECT apps.app_id, apps.version, apps.package_name, submissions.*
        FROM developer_apps AS apps
        LEFT JOIN submissions
            ON submissions.app_id = apps.app_id
            AND submissions.submission_type = 'new'
            AND submissions.status = 'approved'
            AND submissions.developer_id = apps.developer_id
        WHERE apps.app_id = ? AND apps.developer_id = ?
        ORDER BY submissions.id DESC
        LIMIT 1
        """,
        (app_id, session["developer_id"]),
    ).fetchone()
    if not app:
        conn.close()
        return "Приложение не найдено в вашем аккаунте.", 404

    if request.method == "GET":
        pending_update = conn.execute(
            "SELECT 1 FROM submissions WHERE app_id = ? "
            "AND submission_type = 'update' AND status = 'pending'",
            (app_id,),
        ).fetchone()
        conn.close()
        return render_template(
            "developer_update.html",
            app=app,
            pending_update=bool(pending_update),
        )

    pending_update = conn.execute(
        "SELECT 1 FROM submissions WHERE app_id = ? "
        "AND submission_type = 'update' AND status = 'pending'",
        (app_id,),
    ).fetchone()
    if pending_update:
        conn.close()
        flash("Для приложения уже ожидает проверки обновление.", "error")
        return redirect(url_for("developer.dashboard"))

    package = request.files.get("app_file")
    if not package or not package.filename:
        conn.close()
        flash("Выберите пакет приложения.", "error")
        return redirect(url_for("developer.upload_update", app_id=app_id))

    filename = secure_filename(package.filename)
    extension = os.path.splitext(filename)[1].lower()
    if not filename or extension not in {".xap", ".appx", ".appxbundle"}:
        conn.close()
        flash("Поддерживаются пакеты XAP, APPX и APPXBUNDLE.", "error")
        return redirect(url_for("developer.upload_update", app_id=app_id))

    published = find_published_package(
        os.path.join(REPO_PATH, "metadata", app_id),
        app_id,
    )
    current_version = published[1] if published else None
    if not parse_version(current_version):
        conn.close()
        flash(
            "Не удалось определить текущую версию из опубликованного пакета. "
            "Обновление нельзя отправить без проверки версии.",
            "error",
        )
        return redirect(url_for("developer.upload_update", app_id=app_id))

    storage_key = f"{app_id}/{uuid.uuid4().hex}"
    app_pending_dir = os.path.join(PENDING_DIR, app_id, storage_key.split("/")[-1])
    os.makedirs(app_pending_dir, exist_ok=False)
    package_path = os.path.join(app_pending_dir, filename)
    package.save(package_path)

    try:
        incoming = read_package_identity(package_path)
    except (OSError, ValueError, zipfile.BadZipFile, ET.ParseError) as error:
        shutil.rmtree(app_pending_dir)
        conn.close()
        flash(f"Не удалось прочитать манифест пакета: {error}", "error")
        return redirect(url_for("developer.upload_update", app_id=app_id))

    if incoming["app_id"] != app_id:
        shutil.rmtree(app_pending_dir)
        conn.close()
        flash("App ID в пакете не совпадает с выбранным приложением.", "error")
        return redirect(url_for("developer.upload_update", app_id=app_id))
    if not parse_version(incoming.get("version")) or not version_is_newer(
        incoming.get("version"),
        current_version,
    ):
        shutil.rmtree(app_pending_dir)
        conn.close()
        flash(
            f"Новая версия должна быть выше текущей ({current_version}).",
            "error",
        )
        return redirect(url_for("developer.upload_update", app_id=app_id))

    repo_app_dir = os.path.join(REPO_PATH, "metadata", app_id)
    try:
        assets_to_copy = {"icon.png"}
        icon_extension = os.path.splitext(app["temp_icon_name"] or "")[1].lower()
        if (
            app["temp_icon_name"] != app["package_name"]
            and icon_extension in {".png", ".jpg", ".jpeg", ".webp"}
        ):
            assets_to_copy.add(app["temp_icon_name"])
        for asset_name in os.listdir(repo_app_dir):
            source = os.path.join(repo_app_dir, asset_name)
            if asset_name == "screenshots" and os.path.isdir(source):
                shutil.copytree(source, os.path.join(app_pending_dir, asset_name))
            elif asset_name in assets_to_copy or asset_name.startswith("banner"):
                if os.path.isfile(source):
                    shutil.copy2(source, os.path.join(app_pending_dir, asset_name))
    except OSError as error:
        shutil.rmtree(app_pending_dir)
        conn.close()
        flash(f"Не удалось подготовить файлы приложения: {error}", "error")
        return redirect(url_for("developer.upload_update", app_id=app_id))

    conn.execute(
        """
        INSERT INTO submissions (
            app_id, name, temp_app_name, temp_icon_name, developer, category,
            summary_type, summary_static, summary_ru, summary_en,
            desc_type, desc_static, desc_ru, desc_en, manifest_info,
            temp_banner_name, screenshot_names, developer_id, submission_type,
            package_version, storage_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'update', ?, ?)
        """,
        (
            app_id,
            app["name"],
            filename,
            app["temp_icon_name"] or "",
            app["developer"],
            app["category"],
            app["summary_type"],
            app["summary_static"],
            app["summary_ru"],
            app["summary_en"],
            app["desc_type"],
            app["desc_static"],
            app["desc_ru"],
            app["desc_en"],
            None,
            next(
                (
                    asset
                    for asset in os.listdir(app_pending_dir)
                    if asset.startswith("banner")
                ),
                None,
            ),
            app["screenshot_names"],
            session["developer_id"],
            incoming["version"],
            storage_key,
        ),
    )
    conn.commit()
    conn.close()
    flash(f"Обновление {incoming['version']} отправлено на модерацию.", "success")
    return redirect(url_for("developer.dashboard"))


@developer_bp.route("/developer/claims", methods=["POST"])
@developer_required
def submit_claim():
    app_id = request.form.get("app_id", "").strip()
    proof = request.form.get("proof", "").strip()
    if not _APP_ID_PATTERN.fullmatch(app_id):
        flash("Введите корректный App ID.", "error")
        return redirect(url_for("developer.dashboard"))
    if len(proof) < 20 or len(proof) > 4000:
        flash("Добавьте описание доказательств (от 20 до 4000 символов).", "error")
        return redirect(url_for("developer.dashboard"))
    if not os.path.isdir(os.path.join(REPO_PATH, "metadata", app_id)):
        flash("Приложение с таким ID не найдено в каталоге.", "error")
        return redirect(url_for("developer.dashboard"))

    conn = get_connection()
    conn.row_factory = sqlite3.Row
    existing_owner = conn.execute(
        "SELECT developer_id FROM developer_apps WHERE app_id = ?",
        (app_id,),
    ).fetchone()
    if existing_owner and existing_owner["developer_id"] == session["developer_id"]:
        conn.close()
        flash("Это приложение уже связано с вашим аккаунтом.", "success")
        return redirect(url_for("developer.dashboard"))
    try:
        conn.execute(
            """
            INSERT INTO claim_requests (app_id, developer_id, proof)
            VALUES (?, ?, ?)
            ON CONFLICT(app_id, developer_id) DO UPDATE SET
                proof = excluded.proof,
                status = 'pending',
                created_at = CURRENT_TIMESTAMP
            """,
            (app_id, session["developer_id"], proof),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        flash("Не удалось сохранить запрос на подтверждение авторства.", "error")
    else:
        flash("Запрос отправлен модератору.", "success")
    finally:
        conn.close()
    return redirect(url_for("developer.dashboard"))