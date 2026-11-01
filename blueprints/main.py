import json
import os
import re
import shutil
import sqlite3
import xml.etree.ElementTree as ET
import zipfile

from flask import (
    Blueprint,
    abort,
    jsonify,
    render_template,
    request,
    send_from_directory,
    session,
)
from werkzeug.utils import secure_filename

from config import LOCALES_DIR, PENDING_DIR, REPO_PATH, TEMP_DIR
from database import get_connection
from security import valid_csrf_token


main_bp = Blueprint("main", __name__)
_APP_ID_PATTERN = re.compile(r"^(?!\.{1,2}$)[A-Za-z0-9._-]{1,128}$")


def parse_package_manifest(file_path):
    def local_name(tag):
        return tag.split("}")[-1]

    try:
        with zipfile.ZipFile(file_path, "r") as package:
            names = package.namelist()
            if "WMAppManifest.xml" in names:
                root = ET.fromstring(package.read("WMAppManifest.xml"))
                app_node = next(
                    (node for node in root.iter() if local_name(node.tag) == "App"),
                    None,
                )
                if app_node is not None:
                    app_id = app_node.attrib.get("ProductID", "").strip("{}")
                    if not app_id:
                        return {
                            "success": False,
                            "error": "WMAppManifest.xml does not contain a ProductID",
                        }
                    name = app_node.attrib.get("Title", "Unnamed XAP")
                    capabilities = [
                        node.attrib.get("Name") or node.attrib.get("name")
                        for node in root.iter()
                        if local_name(node.tag).lower() == "capability"
                        and (node.attrib.get("Name") or node.attrib.get("name"))
                    ]
                    manifest_info = {
                        "app_type": "xap",
                        "capabilities": capabilities,
                        "product_id": app_id,
                        "title": name,
                        "manifest": "WMAppManifest.xml",
                        "version": app_node.attrib.get("Version"),
                    }
                    return {
                        "success": True,
                        "app_id": app_id,
                        "name": name,
                        "version": app_node.attrib.get("Version"),
                        "manifest_info": manifest_info,
                    }

            appx_manifest = next(
                (
                    filename
                    for filename in (
                        "AppxManifest.xml",
                        "AppxMetadata/AppxBundleManifest.xml",
                    )
                    if filename in names
                ),
                None,
            )
            if appx_manifest:
                root = ET.fromstring(package.read(appx_manifest))
                identity_node = None
                display_name_node = None
                capabilities = []
                applications = []
                minimum_version = None
                for node in root.iter():
                    element_name = local_name(node.tag)
                    if element_name == "Identity":
                        identity_node = node
                    elif element_name == "DisplayName":
                        display_name_node = node
                    elif element_name == "Capability":
                        capability_name = node.attrib.get("Name")
                        if capability_name:
                            capabilities.append(capability_name)
                    elif element_name == "TargetDeviceFamily":
                        minimum_version = node.attrib.get("MinVersion") or minimum_version
                    elif element_name == "Application":
                        applications.append(
                            {
                                key: value
                                for key, value in node.attrib.items()
                                if key in ("Id", "Executable", "EntryPoint", "StartPage")
                            }
                        )

                app_id = (
                    identity_node.attrib.get("Name", "")
                    if identity_node is not None
                    else ""
                )
                if not app_id:
                    return {
                        "success": False,
                        "error": f"{appx_manifest} does not contain an Identity Name",
                    }
                name = (
                    display_name_node.text
                    if display_name_node is not None
                    else (
                        identity_node.attrib.get("Name", "Unnamed APPX")
                        if identity_node is not None
                        else "Unnamed APPX"
                    )
                )
                manifest_info = {
                    "app_type": (
                        "uwp_bundle"
                        if appx_manifest.endswith("AppxBundleManifest.xml")
                        else "uwp"
                    ),
                    "capabilities": capabilities,
                    "minimum_version": minimum_version or "не указана",
                    "applications": applications,
                    "identity": dict(identity_node.attrib) if identity_node is not None else {},
                    "manifest": appx_manifest,
                    "version": (
                        identity_node.attrib.get("Version")
                        if identity_node is not None
                        else None
                    ),
                }
                return {
                    "success": True,
                    "app_id": app_id,
                    "name": name,
                    "version": manifest_info["version"],
                    "manifest_info": manifest_info,
                }
    except Exception as error:
        print(f"Ошибка встроенного парсинга: {error}")

    return {
        "success": False,
        "error": "Не удалось найти или прочитать файл манифеста внутри архива",
    }


@main_bp.route("/")
def index():
    return render_template("index.html")


@main_bp.route("/locales/<locale>.json")
def locale_file(locale):
    if locale not in {"ru", "en"}:
        abort(404)
    return send_from_directory(LOCALES_DIR, f"{locale}.json", mimetype="application/json")


@main_bp.route("/parse-package", methods=["POST"])
def parse_package():
    if "app_file" not in request.files:
        return jsonify({"success": False, "error": "Файл не найден"}), 400

    file = request.files["app_file"]
    if file.filename == "":
        return jsonify({"success": False, "error": "Файл не выбран"}), 400

    temp_file_name = secure_filename(file.filename)
    if not temp_file_name:
        return jsonify({"success": False, "error": "Некорректное имя файла"}), 400
    temp_path = os.path.join(TEMP_DIR, temp_file_name)
    file.save(temp_path)

    parse_result = parse_package_manifest(temp_path)
    if parse_result.get("success"):
        return jsonify(
            {
                "success": True,
                "app_id": parse_result["app_id"],
                "name": parse_result["name"],
                "temp_file_name": temp_file_name,
                "manifest_info": parse_result.get("manifest_info", {}),
            }
        )

    if os.path.exists(temp_path):
        os.remove(temp_path)
    return jsonify(
        {
            "success": False,
            "error": f"Не удалось распарсить манифест: {parse_result.get('error')}",
        }
    ), 400


@main_bp.route("/upload", methods=["POST"])
def upload_app():
    app_id = request.form.get("app_id")
    temp_file_name = request.form.get("temp_file_name")
    name = request.form.get("name")
    developer = request.form.get("developer")
    category = request.form.get("category")
    summary_type = request.form.get("summary_type")
    summary_static = request.form.get("summary_static")
    summary_ru = request.form.get("summary_ru")
    summary_en = request.form.get("summary_en")
    desc_type = request.form.get("desc_type")
    desc_static = request.form.get("desc_static")
    desc_ru = request.form.get("desc_ru")
    desc_en = request.form.get("desc_en")

    icon_file = request.files.get("icon_file")
    banner_file = request.files.get("banner_file")
    screenshot_files = [
        file for file in request.files.getlist("screenshots") if file and file.filename
    ]
    allowed_image_extensions = {".png", ".jpg", ".jpeg", ".webp"}

    if not app_id or not _APP_ID_PATTERN.fullmatch(app_id):
        return jsonify({"error": "Некорректный идентификатор приложения"}), 400
    if not temp_file_name or secure_filename(temp_file_name) != temp_file_name:
        return jsonify({"error": "Некорректное имя файла пакета"}), 400
    if not icon_file or not icon_file.filename:
        return jsonify({"error": "Иконка приложения не выбрана"}), 400
    if session.get("developer_id") and not valid_csrf_token(
        request.form.get("csrf_token")
    ):
        return jsonify({"error": "Сессия формы устарела. Обновите страницу."}), 400

    src_temp_path = os.path.join(TEMP_DIR, temp_file_name)
    if not os.path.exists(src_temp_path):
        return jsonify({"error": "Временный файл пакета потерян, загрузите заново"}), 400

    parsed_manifest = parse_package_manifest(src_temp_path)
    if not parsed_manifest.get("success"):
        return jsonify({"error": "Не удалось повторно проверить манифест пакета"}), 400
    if parsed_manifest["app_id"] != app_id:
        return jsonify({"error": "Идентификатор приложения не совпадает с манифестом"}), 400
    manifest_info = json.dumps(parsed_manifest.get("manifest_info", {}), ensure_ascii=False)
    developer_id = session.get("developer_id")
    account_conn = get_connection()
    account_conn.row_factory = sqlite3.Row
    existing_owner = account_conn.execute(
        "SELECT developer_id FROM developer_apps WHERE app_id = ?",
        (app_id,),
    ).fetchone()
    pending_submission = account_conn.execute(
        "SELECT 1 FROM submissions WHERE app_id = ? "
        "AND submission_type = 'new' AND status = 'pending'",
        (app_id,),
    ).fetchone()
    if developer_id:
        if not _APP_ID_PATTERN.fullmatch(parsed_manifest["app_id"]):
            account_conn.close()
            return jsonify({"error": "Идентификатор приложения в манифесте некорректен"}), 400
        account = account_conn.execute(
            "SELECT publisher_name FROM developers WHERE id = ?",
            (developer_id,),
        ).fetchone()
        if not account:
            account_conn.close()
            session.clear()
            return jsonify({"error": "Сессия разработчика истекла. Войдите снова."}), 401
        developer = account["publisher_name"]
    account_conn.close()
    if existing_owner:
        return jsonify(
            {"error": "Это приложение уже закреплено за разработчиком. Подтвердите авторство в кабинете."}
        ), 409
    if pending_submission:
        return jsonify(
            {"error": "Заявка на это приложение уже ожидает проверки."}
        ), 409
    if os.path.isfile(os.path.join(REPO_PATH, "metadata", app_id, "metadata.yaml")):
        return jsonify(
            {"error": "Приложение уже есть в каталоге. Отправьте запрос на подтверждение авторства."}
        ), 409

    if banner_file and banner_file.filename:
        extension = os.path.splitext(secure_filename(banner_file.filename))[1].lower()
        if extension not in allowed_image_extensions:
            return jsonify({"error": "Баннер должен быть PNG, JPG или WEBP"}), 400

    for screenshot in screenshot_files:
        extension = os.path.splitext(secure_filename(screenshot.filename))[1].lower()
        if extension not in allowed_image_extensions:
            return jsonify({"error": "Скриншоты должны быть PNG, JPG или WEBP"}), 400

    app_pending_dir = os.path.join(PENDING_DIR, app_id)
    os.makedirs(app_pending_dir, exist_ok=True)
    shutil.move(src_temp_path, os.path.join(app_pending_dir, temp_file_name))

    icon_filename = "icon.png"
    icon_file.save(os.path.join(app_pending_dir, icon_filename))

    banner_filename = None
    if banner_file and banner_file.filename:
        extension = os.path.splitext(secure_filename(banner_file.filename))[1].lower()
        banner_filename = f"banner{extension}"
        banner_file.save(os.path.join(app_pending_dir, banner_filename))

    screenshot_names = []
    if screenshot_files:
        screenshots_dir = os.path.join(app_pending_dir, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        for index, screenshot in enumerate(screenshot_files, start=1):
            original_name = secure_filename(screenshot.filename)
            extension = os.path.splitext(original_name)[1].lower()
            screenshot_name = f"screenshot_{index}{extension}"
            screenshot.save(os.path.join(screenshots_dir, screenshot_name))
            screenshot_names.append(screenshot_name)

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO submissions (
            app_id, name, temp_app_name, temp_icon_name, developer, category,
            summary_type, summary_static, summary_ru, summary_en,
            desc_type, desc_static, desc_ru, desc_en, manifest_info,
            temp_banner_name, screenshot_names, developer_id, submission_type,
            package_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)
        """,
        (
            app_id, name, temp_file_name, icon_filename, developer, category,
            summary_type, summary_static, summary_ru, summary_en,
            desc_type, desc_static, desc_ru, desc_en, manifest_info,
            banner_filename, json.dumps(screenshot_names, ensure_ascii=False),
            developer_id, parsed_manifest.get("version"),
        ),
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "success", "message": "Приложение отправлено на модерацию!"})