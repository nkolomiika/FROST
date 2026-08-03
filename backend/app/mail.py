import base64
import time
from email.message import EmailMessage
from email.utils import formataddr
from pathlib import Path

import aiosmtplib
import httpx

from app.config import get_settings

settings = get_settings()

# Access-токен Google живёт ~1 час. Кешируем его в памяти процесса, чтобы не
# дёргать token endpoint на каждое письмо. Ключ — refresh token, поэтому смена
# аккаунта в .env автоматически инвалидирует кеш.
_oauth_token_cache: dict[str, tuple[str, float]] = {}


# ---------------------------------------------------------------------------
# Вёрстка писем. Почтовые клиенты не поддерживают внешние CSS и современные
# свойства, поэтому только таблицы + инлайновые стили, без картинок (логотип —
# текстовый, иначе его пришлось бы где-то хостить и он бы резался блокировкой
# внешних ресурсов). Цвета — фирменные STORM.
# ---------------------------------------------------------------------------
BRAND = "STORM"
ACCENT = "#2E5FBF"
INK = "#0F1B2D"
MUTED = "#5A6B84"
FAINT = "#8A97AB"
FOOTER = "Licensed to SberTech · Copyright © 2026. All rights reserved."

# Логотип вкладывается в письмо и подключается через cid: — внешние картинки
# почтовики блокируют по умолчанию, а SVG (как в вебе) Gmail вырезает совсем.
# Версия белая и лежит на тёмной плашке: тёмная тема почты инвертирует текст,
# но НЕ картинки, поэтому тёмный логотип на инвертированном фоне пропадал.
# Явно тёмный фон шапки клиенты не инвертируют — белое остаётся читаемым везде.
LOGO_CID = "sbermark"
LOGO_PATH = Path(__file__).parent / "assets" / "sber-mark-white.png"


def load_logo_bytes() -> bytes | None:
    """Читает PNG-логотип. None — если файла нет: письмо уйдёт без картинки."""
    try:
        return LOGO_PATH.read_bytes()
    except OSError:
        return None


def _html_shell(*, heading: str, intro: str, inner: str, outro: str) -> str:
    """Общий каркас письма: шапка (лого SberTech + STORM), карточка, подвал."""
    return f"""\
<!doctype html>
<html lang="ru">
<body style="margin:0;padding:0;background:#eef1f6;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#eef1f6;padding:32px 12px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:520px;">
        <tr><td align="center" style="padding-bottom:18px;">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center" style="background:{INK};border-radius:14px;">
            <tr><td style="padding:12px 22px;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td style="padding-right:10px;" valign="middle">
                    <img src="cid:{LOGO_CID}" width="26" height="26" alt="SberTech" style="display:block;border:0;outline:none;text-decoration:none;">
                  </td>
                  <td valign="middle">
                    <span style="font:800 20px/1 Arial,Helvetica,sans-serif;letter-spacing:3px;color:#ffffff;">{BRAND}</span>
                  </td>
                </tr>
              </table>
            </td></tr>
          </table>
        </td></tr>
        <tr><td style="background:#ffffff;border:1px solid #e9edf4;border-radius:16px;padding:32px 34px;">
          <h1 style="margin:0 0 14px;font:800 22px/1.3 Arial,Helvetica,sans-serif;color:{INK};">{heading}</h1>
          <p style="margin:0 0 22px;font:400 15px/1.6 Arial,Helvetica,sans-serif;color:{MUTED};">{intro}</p>
          {inner}
          <p style="margin:24px 0 0;font:400 13px/1.6 Arial,Helvetica,sans-serif;color:{FAINT};">{outro}</p>
        </td></tr>
        <tr><td align="center" style="padding-top:18px;font:400 12px/1.6 Arial,Helvetica,sans-serif;color:#a0abbd;">
          <span style="font-weight:700;color:#7c8aa0;">{BRAND}</span> · {FOOTER}<br>
          Это письмо отправлено автоматически, отвечать на него не нужно.
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""


def _button(url: str, label: str) -> str:
    """Кнопка-ссылка по центру. Внешняя таблица на всю ширину + align=center —
    так её центрируют и Outlook, и клиенты, игнорирующие margin:auto."""
    return f"""\
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr><td align="center" style="padding:2px 0;">
              <table role="presentation" cellpadding="0" cellspacing="0" border="0" align="center">
                <tr><td align="center" style="border-radius:12px;background:{ACCENT};">
                  <a href="{url}" style="display:inline-block;padding:14px 30px;font:700 15px/1 Arial,Helvetica,sans-serif;color:#ffffff;text-decoration:none;border-radius:12px;">{label}</a>
                </td></tr>
              </table>
            </td></tr>
          </table>"""


def build_temporary_password_email(*, username: str, temporary_password: str) -> tuple[str, str, str]:
    """Письмо со временным паролем. Возвращает (subject, text, html)."""
    subject = f"{BRAND}: временный пароль"
    text = (
        f"Здравствуйте, {username}!\n\n"
        f"Для вашей учётной записи в {BRAND} создан или сброшен пароль.\n"
        f"Временный пароль: {temporary_password}\n\n"
        "При первом входе система попросит задать новый пароль.\n"
        "Если вы не ожидали это письмо, свяжитесь с администратором."
    )
    inner = f"""\
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
            <tr><td style="background:#f6f8fc;border:1px solid #e9edf4;border-radius:10px;padding:14px 18px;">
              <div style="font:700 11px/1 Arial,Helvetica,sans-serif;letter-spacing:1px;color:{FAINT};text-transform:uppercase;padding-bottom:8px;">Временный пароль</div>
              <div style="font:700 20px/1.3 'Courier New',Courier,monospace;color:{INK};letter-spacing:1px;">{temporary_password}</div>
            </td></tr>
          </table>"""
    html = _html_shell(
        heading="Временный пароль",
        intro=f"Здравствуйте, {username}! Для вашей учётной записи в {BRAND} создан или сброшен пароль.",
        inner=inner,
        outro="При первом входе система попросит задать новый пароль. Если вы не ожидали это письмо, свяжитесь с администратором.",
    )
    return subject, text, html


def build_invitation_email(*, recipient_email: str, full_name: str | None, activation_url: str) -> tuple[str, str, str]:
    """Письмо-приглашение с кнопкой активации. Возвращает (subject, text, html)."""
    greeting = f"Здравствуйте, {full_name}!" if full_name else "Здравствуйте!"
    subject = f"Приглашение в {BRAND}"
    text = (
        f"{greeting}\n\n"
        f"Вас пригласили в {BRAND}. Чтобы завершить регистрацию, перейдите по ссылке "
        "ниже и задайте себе имя пользователя и пароль:\n\n"
        f"{activation_url}\n\n"
        "Ссылка одноразовая и действует ограниченное время. Если вы не ожидали это "
        "приглашение, просто проигнорируйте письмо."
    )
    # Дублируем ссылку текстом: часть клиентов режет кнопки, плюс её удобно скопировать.
    inner = _button(activation_url, "Активировать аккаунт") + f"""
          <p style="margin:22px 0 0;font:400 13px/1.6 Arial,Helvetica,sans-serif;color:{FAINT};">
            Если кнопка не открывается, скопируйте ссылку в браузер:<br>
            <a href="{activation_url}" style="color:{ACCENT};word-break:break-all;">{activation_url}</a>
          </p>"""
    html = _html_shell(
        heading=f"Добро пожаловать в {BRAND}!",
        intro=f"{greeting} Вас пригласили в {BRAND}. Осталось задать имя пользователя и пароль — нажмите кнопку ниже.",
        inner=inner,
        outro="Ссылка одноразовая и действует ограниченное время. Если вы не ожидали это приглашение, просто проигнорируйте письмо.",
    )
    return subject, text, html


def build_password_reset_email(*, username: str, reset_url: str, expire_hours: int) -> tuple[str, str, str]:
    """Письмо «забыли пароль» с кнопкой. Возвращает (subject, text, html)."""
    subject = f"{BRAND}: восстановление пароля"
    text = (
        f"Здравствуйте, {username}!\n\n"
        f"Мы получили запрос на восстановление пароля в {BRAND}. Чтобы задать новый "
        "пароль, перейдите по ссылке:\n\n"
        f"{reset_url}\n\n"
        f"Ссылка одноразовая и действует {expire_hours} ч.\n"
        "Если вы не запрашивали восстановление, просто проигнорируйте письмо — "
        "пароль останется прежним."
    )
    inner = _button(reset_url, "Задать новый пароль") + f"""
          <p style="margin:22px 0 0;font:400 13px/1.6 Arial,Helvetica,sans-serif;color:{FAINT};">
            Если кнопка не открывается, скопируйте ссылку в браузер:<br>
            <a href="{reset_url}" style="color:{ACCENT};word-break:break-all;">{reset_url}</a>
          </p>"""
    html = _html_shell(
        heading="Восстановление пароля",
        intro=f"Здравствуйте, {username}! Мы получили запрос на восстановление пароля в {BRAND}. Нажмите кнопку ниже, чтобы задать новый.",
        inner=inner,
        outro=(
            f"Ссылка одноразовая и действует {expire_hours} ч. Если вы не запрашивали "
            "восстановление, просто проигнорируйте письмо — пароль останется прежним."
        ),
    )
    return subject, text, html


def build_reactivation_email(*, username: str, reactivate_url: str, expire_hours: int) -> tuple[str, str, str]:
    """Письмо «с возвращением» — кнопка возвращает доступ. Возвращает (subject, text, html)."""
    subject = f"{BRAND}: возвращение доступа"
    text = (
        f"С возвращением, {username}!\n\n"
        f"Ваш доступ в {BRAND} восстановлен. Чтобы войти в аккаунт, перейдите по ссылке — "
        "она сразу откроет ваш рабочий кабинет:\n\n"
        f"{reactivate_url}\n\n"
        f"Ссылка одноразовая и действует {expire_hours} ч.\n"
        "Если вы не ожидали этого письма, просто проигнорируйте его."
    )
    inner = _button(reactivate_url, "Вернуться в аккаунт") + f"""
          <p style="margin:22px 0 0;font:400 13px/1.6 Arial,Helvetica,sans-serif;color:{FAINT};">
            Если кнопка не открывается, скопируйте ссылку в браузер:<br>
            <a href="{reactivate_url}" style="color:{ACCENT};word-break:break-all;">{reactivate_url}</a>
          </p>"""
    html = _html_shell(
        heading="С возвращением",
        intro=f"С возвращением, {username}! Ваш доступ в {BRAND} восстановлен. Нажмите кнопку ниже, чтобы войти в аккаунт.",
        inner=inner,
        outro=(
            f"Ссылка одноразовая и действует {expire_hours} ч. Если вы не ожидали "
            "этого письма, просто проигнорируйте его."
        ),
    )
    return subject, text, html


async def _get_oauth_access_token() -> str:
    """Обменивает refresh token на короткоживущий access token (с кешированием)."""
    for field in ("google_oauth_client_id", "google_oauth_client_secret", "google_oauth_refresh_token"):
        if not getattr(settings, field):
            raise RuntimeError(f"SMTP_AUTH_METHOD=xoauth2 требует заполненного {field.upper()} в .env")

    refresh_token = settings.google_oauth_refresh_token
    cached = _oauth_token_cache.get(refresh_token)
    now = time.monotonic()
    if cached and now < cached[1]:
        return cached[0]

    async with httpx.AsyncClient(timeout=settings.smtp_timeout_seconds) as client:
        response = await client.post(
            settings.google_oauth_token_uri,
            data={
                "client_id": settings.google_oauth_client_id,
                "client_secret": settings.google_oauth_client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
        )
    if response.status_code != 200:
        # Тело содержит {"error": "...", "error_description": "..."} — полезно для диагностики
        # (invalid_grant = refresh token отозван/протух, нужно заново пройти consent).
        raise RuntimeError(f"Google OAuth token refresh failed ({response.status_code}): {response.text}")

    data = response.json()
    access_token = data["access_token"]
    # 60 секунд запаса на сетевые задержки, чтобы не отправить с истекающим токеном.
    expires_at = now + max(0, int(data.get("expires_in", 3600)) - 60)
    _oauth_token_cache[refresh_token] = (access_token, expires_at)
    return access_token


async def _send_via_xoauth2(message: EmailMessage, *, use_tls: bool, start_tls: bool) -> None:
    """Отправка через SMTP AUTH XOAUTH2 (Gmail и др. OAuth2-провайдеры)."""
    # Для XOAUTH2 username — это адрес аутентифицируемого аккаунта. Берём из
    # SMTP_USERNAME, иначе из From-адреса.
    username = settings.smtp_username or settings.smtp_from_email
    access_token = await _get_oauth_access_token()
    auth_string = base64.b64encode(
        f"user={username}\x01auth=Bearer {access_token}\x01\x01".encode("utf-8")
    )

    smtp = aiosmtplib.SMTP(
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        use_tls=use_tls,
        start_tls=start_tls,
        timeout=settings.smtp_timeout_seconds,
    )
    async with smtp:  # connect(): greeting + EHLO (+ STARTTLS при start_tls=True)
        response = await smtp.execute_command(b"AUTH", b"XOAUTH2", auth_string)
        if response.code != 235:
            # При ошибке Gmail отвечает 334 с base64-JSON описанием; чтобы получить
            # финальный код (обычно 535), нужно послать пустую строку-подтверждение.
            if response.code == 334:
                response = await smtp.execute_command(b"")
            raise aiosmtplib.SMTPAuthenticationError(response.code, response.message)
        await smtp.send_message(message)


async def send_plain_text_email(
    *, recipient_email: str, subject: str, body: str, html_body: str | None = None
) -> None:
    """Отправляет письмо. При наличии html_body уходит multipart/alternative:
    текстовая часть — фолбэк для клиентов без HTML."""
    message = EmailMessage()
    # formataddr корректно кодирует кириллицу и спец-символы в display name
    # (RFC 2047/5322). Прямая f-string «{name} <{email}>» ломалась бы на запятых.
    message["From"] = formataddr((settings.smtp_from_name, settings.smtp_from_email))
    message["To"] = recipient_email
    message["Subject"] = subject
    message.set_content(body, charset="utf-8")
    if html_body:
        message.add_alternative(html_body, subtype="html", charset="utf-8")
        logo = load_logo_bytes()
        if logo:
            # add_related на HTML-части превращает её в multipart/related, где
            # картинка лежит рядом с разметкой и доступна по cid. Заголовок
            # Content-ID email-пакет оборачивает в <>, в src его писать не нужно.
            html_part = message.get_payload()[-1]
            html_part.add_related(
                logo,
                maintype="image",
                subtype="png",
                cid=f"<{LOGO_CID}>",
                filename="sber-mark.png",
                disposition="inline",
            )
    # Порт 465 → implicit TLS (use_tls=True). Порт 587 → STARTTLS (start_tls=True).
    use_tls = bool(settings.smtp_use_ssl)
    start_tls = bool(settings.smtp_use_tls) and not use_tls

    if settings.smtp_auth_method == "xoauth2":
        await _send_via_xoauth2(message, use_tls=use_tls, start_tls=start_tls)
        return

    await aiosmtplib.send(
        message,
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_username or None,
        password=settings.smtp_password or None,
        use_tls=use_tls,
        start_tls=start_tls,
        timeout=settings.smtp_timeout_seconds,
    )
