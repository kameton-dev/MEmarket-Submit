import sqlite3

from config import DATABASE_PATH


def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id TEXT NOT NULL,
            name TEXT NOT NULL,
            temp_app_name TEXT NOT NULL,
            temp_icon_name TEXT NOT NULL,
            developer TEXT NOT NULL,
            category TEXT NOT NULL,
            summary_type TEXT NOT NULL,
            summary_static TEXT,
            summary_ru TEXT,
            summary_en TEXT,
            desc_type TEXT NOT NULL,
            desc_static TEXT,
            desc_ru TEXT,
            desc_en TEXT,
            status TEXT DEFAULT 'pending'
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS developers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL COLLATE NOCASE UNIQUE,
            password_hash TEXT NOT NULL,
            publisher_name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS developer_apps (
            app_id TEXT PRIMARY KEY,
            developer_id INTEGER NOT NULL REFERENCES developers(id) ON DELETE CASCADE,
            version TEXT,
            package_name TEXT,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS claim_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id TEXT NOT NULL,
            developer_id INTEGER NOT NULL REFERENCES developers(id) ON DELETE CASCADE,
            proof TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(app_id, developer_id)
        )
        """
    )
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(submissions)")}
    if "manifest_info" not in columns:
        cursor.execute("ALTER TABLE submissions ADD COLUMN manifest_info TEXT")
    if "temp_banner_name" not in columns:
        cursor.execute("ALTER TABLE submissions ADD COLUMN temp_banner_name TEXT")
    if "screenshot_names" not in columns:
        cursor.execute("ALTER TABLE submissions ADD COLUMN screenshot_names TEXT")
    if "developer_id" not in columns:
        cursor.execute(
            "ALTER TABLE submissions ADD COLUMN developer_id INTEGER "
            "REFERENCES developers(id) ON DELETE SET NULL"
        )
    if "submission_type" not in columns:
        cursor.execute(
            "ALTER TABLE submissions ADD COLUMN submission_type TEXT NOT NULL DEFAULT 'new'"
        )
    if "package_version" not in columns:
        cursor.execute("ALTER TABLE submissions ADD COLUMN package_version TEXT")
    if "storage_key" not in columns:
        cursor.execute("ALTER TABLE submissions ADD COLUMN storage_key TEXT")
    conn.commit()
    conn.close()
