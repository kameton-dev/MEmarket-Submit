import hashlib
import re
import sqlite3
from functools import wraps

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_connection
from security import valid_csrf_token

moderator_bp = Blueprint("moderator", __name__)
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@moderator_bp.before_request
def protect_posts():
    if request.method == "POST" and not valid_csrf_token(request.form.get("csrf_token")):
        return "Форма устарела. Обновите страницу и повторите попытку.", 400


def moderator_required(view):
    @wraps(view)
    def decorated(*args, **kwargs):
        moderator_id = session.get("moderator_id")
        if not moderator_id:
            return redirect(url_for("moderator.login"))
        conn = get_connection()
        row = conn.execute("SELECT status FROM moderators WHERE id=?", (moderator_id,)).fetchone()
        conn.close()
        if not row or row[0] != "active":
            session.pop("moderator_id", None)
            flash("Аккаунт ещё не одобрен администратором.", "error")
            return redirect(url_for("moderator.login"))
        return view(*args, **kwargs)
    return decorated


@moderator_bp.route("/moderator/register/<token>", methods=["GET", "POST"])
def register(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = get_connection()
    invitation = conn.execute(
        "SELECT id FROM moderator_invitations WHERE token_hash=? AND used_at IS NULL "
        "AND expires_at > CURRENT_TIMESTAMP", (token_hash,)
    ).fetchone()
    if not invitation:
        conn.close()
        return render_template("moderator_auth.html", mode="register", token=None,
                               error="Ссылка приглашения недействительна или уже использована."), 410
    if request.method == "GET":
        conn.close()
        return render_template("moderator_auth.html", mode="register", token=token)

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not _EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        conn.close()
        return render_template("moderator_auth.html", mode="register", token=token,
                               error="Введите корректный email."), 400
    if len(password) < 12:
        conn.close()
        return render_template("moderator_auth.html", mode="register", token=token,
                               error="Пароль должен содержать не менее 12 символов."), 400
    try:
        conn.execute("BEGIN IMMEDIATE")
        valid = conn.execute(
            "SELECT id FROM moderator_invitations WHERE id=? AND used_at IS NULL "
            "AND expires_at > CURRENT_TIMESTAMP", (invitation[0],)
        ).fetchone()
        if not valid:
            conn.rollback()
            conn.close()
            return render_template("moderator_auth.html", mode="register", token=None,
                                   error="Ссылка приглашения уже использована."), 410
        conn.execute("INSERT INTO moderators(email,password_hash,status) VALUES(?,?,'pending')",
                     (email, generate_password_hash(password)))
        conn.execute("UPDATE moderator_invitations SET used_at=CURRENT_TIMESTAMP WHERE id=?",
                     (invitation[0],))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        conn.close()
        return render_template("moderator_auth.html", mode="register", token=token,
                               error="Аккаунт с таким email уже существует."), 409
    conn.close()
    session.clear()
    return render_template("moderator_auth.html", mode="pending", token=None)


@moderator_bp.route("/moderator/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("moderator_auth.html", mode="login", token=None)
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    moderator = conn.execute("SELECT id,password_hash,status FROM moderators WHERE email=?", (email,)).fetchone()
    conn.close()
    if not moderator or not check_password_hash(moderator["password_hash"], password):
        return render_template("moderator_auth.html", mode="login", token=None,
                               error="Неверный email или пароль."), 401
    if moderator["status"] != "active":
        return render_template("moderator_auth.html", mode="login", token=None,
                               error="Аккаунт ожидает одобрения администратора."), 403
    session.clear()
    session["moderator_id"] = moderator["id"]
    return redirect(url_for("moderator.dashboard"))


@moderator_bp.route("/moderator/logout", methods=["POST"])
@moderator_required
def logout():
    session.clear()
    return redirect(url_for("moderator.login"))


@moderator_bp.route("/moderator")
@moderator_required
def dashboard():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    moderator = conn.execute("SELECT email FROM moderators WHERE id=?", (session["moderator_id"],)).fetchone()
    submissions = conn.execute(
        "SELECT id,app_id,name,developer,category,temp_icon_name,temp_app_name,storage_key,submission_type,package_version "
        "FROM submissions WHERE status='pending' ORDER BY id"
    ).fetchall()
    conn.close()
    return render_template("moderator_dashboard.html", moderator=moderator, submissions=submissions)
