import os

from flask import Flask

from blueprints.admin import admin_bp
from blueprints.developer import developer_bp
from blueprints.main import main_bp
from config import SECRET_KEY, SESSION_COOKIE_SECURE, TEMP_DIR
from database import init_db


def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=SECRET_KEY,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=SESSION_COOKIE_SECURE,
    )
    os.makedirs(TEMP_DIR, exist_ok=True)
    init_db()

    @app.context_processor
    def inject_csrf_token():
        from security import get_csrf_token

        return {"csrf_token": get_csrf_token}

    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(developer_bp)
    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
