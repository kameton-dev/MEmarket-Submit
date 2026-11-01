import os
import secrets


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_PATH = os.environ.get(
    "MEMARKET_REPO_PATH",
    "/var/www/memarket-basic",
)
PENDING_DIR = os.path.join(BASE_DIR, "pending_uploads")
TEMP_DIR = os.path.join(PENDING_DIR, "temp")
LOCALES_DIR = os.path.join(BASE_DIR, "locales")
DATABASE_PATH = os.path.join(BASE_DIR, "database.db")

ADMIN_USER = os.environ.get("ADMIN_USER")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "").lower() in {
    "1",
    "true",
    "yes",
}
