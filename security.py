import hmac
import secrets

from flask import session


def get_csrf_token():
    token = session.get("_csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def valid_csrf_token(token):
    expected = session.get("_csrf_token")
    return bool(expected and token and hmac.compare_digest(expected, token))