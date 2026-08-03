#!/usr/bin/env python3
"""Однократный OAuth2-consent для отправки писем от лица Google-аккаунта.

Что делает:
  1. Открывает браузер на экране согласия Google.
  2. Ловит редирект на локальный loopback-сервер и забирает authorization code.
  3. Меняет code на refresh token (+ access token).
  4. По access-токену узнаёт адрес аккаунта (Gmail getProfile).
  5. Печатает готовый блок для .env.

Перед запуском в Google Cloud Console → APIs & Services → Credentials → ваш
OAuth client (тип «Web») → Authorized redirect URIs добавьте:

    http://localhost:8765/oauth2callback

client_id / client_secret берутся из .env (GOOGLE_OAUTH_CLIENT_ID /
GOOGLE_OAUTH_CLIENT_SECRET) либо из флагов --client-id / --client-secret.

Запуск:
    python backend/scripts/google_oauth_setup.py
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import secrets
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path


def _http_json(url: str, *, data: dict | None = None, headers: dict | None = None) -> tuple[int, dict, str]:
    """Мини-обёртка над urllib: только стандартная библиотека, чтобы скрипт
    запускался на любом python3 без установки зависимостей.
    Возвращает (status, json_или_пусто, сырой_текст)."""
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8", errors="replace")
            status = response.status
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        status = exc.code
    except urllib.error.URLError as exc:
        return 0, {}, f"сеть недоступна: {exc.reason}"
    try:
        return status, json.loads(raw), raw
    except ValueError:
        return status, {}, raw

AUTH_URI = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URI = "https://oauth2.googleapis.com/token"
GMAIL_PROFILE_URI = "https://gmail.googleapis.com/gmail/v1/users/me/profile"
# Для SMTP XOAUTH2 Gmail требует именно полный mail-scope, gmail.send не подходит.
SCOPE = "https://mail.google.com/"
CALLBACK_PATH = "/oauth2callback"


def _read_env_file(env_path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not env_path.exists():
        return values
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    return values


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    result: dict[str, str] = {}
    done = threading.Event()

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != CALLBACK_PATH:
            self.send_response(404)
            self.end_headers()
            return
        query = urllib.parse.parse_qs(parsed.query)
        _CallbackHandler.result = {k: v[0] for k, v in query.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        ok = "code" in _CallbackHandler.result
        body = (
            "<h2>Готово ✅</h2><p>Авторизация получена, вернитесь в терминал.</p>"
            if ok
            else "<h2>Ошибка</h2><p>Google не вернул authorization code.</p>"
        )
        self.wfile.write(f"<!doctype html><meta charset='utf-8'>{body}".encode("utf-8"))
        _CallbackHandler.done.set()

    def log_message(self, *_args) -> None:  # приглушаем access-лог сервера
        pass


def main() -> int:
    project_root = Path(__file__).resolve().parents[2]
    env = _read_env_file(project_root / ".env")

    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--client-id", default=env.get("GOOGLE_OAUTH_CLIENT_ID", ""))
    parser.add_argument("--client-secret", default=env.get("GOOGLE_OAUTH_CLIENT_SECRET", ""))
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="localhost")
    args = parser.parse_args()

    if not args.client_id or not args.client_secret:
        print(
            "Не заданы client_id/client_secret. Заполните GOOGLE_OAUTH_CLIENT_ID и "
            "GOOGLE_OAUTH_CLIENT_SECRET в .env или передайте --client-id/--client-secret.",
            file=sys.stderr,
        )
        return 2

    redirect_uri = f"http://{args.host}:{args.port}{CALLBACK_PATH}"
    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()

    auth_url = AUTH_URI + "?" + urllib.parse.urlencode(
        {
            "client_id": args.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": SCOPE,
            "access_type": "offline",   # обязательно, иначе не выдадут refresh token
            "prompt": "consent",        # форсируем выдачу refresh token при повторном запуске
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )

    server = http.server.HTTPServer((args.host, args.port), _CallbackHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

    print("Откройте ссылку в браузере (если он не открылся сам):\n")
    print(f"  {auth_url}\n")
    print(f"Ожидаю редирект на {redirect_uri} ...")
    try:
        webbrowser.open(auth_url)
    except Exception:
        pass

    if not _CallbackHandler.done.wait(timeout=300):
        print("Не дождались ответа за 5 минут. Прервано.", file=sys.stderr)
        server.shutdown()
        return 1
    server.shutdown()

    result = _CallbackHandler.result
    if result.get("state") != state:
        print("state не совпал — возможна подмена ответа. Прервано.", file=sys.stderr)
        return 1
    if "code" not in result:
        print(f"Google вернул ошибку: {result.get('error', 'unknown')}", file=sys.stderr)
        return 1

    status, tokens, raw = _http_json(
        TOKEN_URI,
        data={
            "client_id": args.client_id,
            "client_secret": args.client_secret,
            "code": result["code"],
            "code_verifier": verifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        },
    )
    if status != 200:
        print(f"Обмен кода не удался ({status}): {raw}", file=sys.stderr)
        return 1
    refresh_token = tokens.get("refresh_token")
    access_token = tokens.get("access_token")
    if not refresh_token:
        print(
            "Google не вернул refresh_token. Обычно это значит, что доступ уже был выдан ранее.\n"
            "Зайдите на https://myaccount.google.com/permissions, удалите доступ приложения и "
            "запустите скрипт снова.",
            file=sys.stderr,
        )
        return 1

    email = "<ваш-gmail>"
    profile_status, profile, _ = _http_json(
        GMAIL_PROFILE_URI, headers={"Authorization": f"Bearer {access_token}"}
    )
    if profile_status == 200:
        email = profile.get("emailAddress", email)

    print("\n" + "=" * 68)
    print("Успех. Вставьте/обновите эти строки в .env:\n")
    print(f"SMTP_AUTH_METHOD=xoauth2")
    print(f"SMTP_HOST=smtp.gmail.com")
    print(f"SMTP_PORT=587")
    print(f"SMTP_USE_TLS=true")
    print(f"SMTP_USE_SSL=false")
    print(f"SMTP_USERNAME={email}")
    print(f"SMTP_FROM_EMAIL={email}")
    print(f"GOOGLE_OAUTH_REFRESH_TOKEN={refresh_token}")
    print("=" * 68)
    print("\nЗатем перезапустите mail-worker:  docker compose restart mail-worker")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
