import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from io import BytesIO

import pyotp
import qrcode
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import get_settings
from app.exceptions import UnauthorizedError

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = get_settings()

# Тип и время жизни промежуточного токена между шагами логина: пароль уже
# проверен, но код TOTP ещё нет. Держим короткоживущим — это «наполовину
# авторизованное» состояние, не полноценная сессия.
TWO_FA_PENDING_TYPE = "2fa_pending"
TWO_FA_PENDING_TTL_MINUTES = 5
TOTP_ISSUER = "STORM"


def hash_password(password: str) -> str:
    """Хэширует пароль пользователя с использованием bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверяет соответствие пароля его bcrypt-хэшу."""
    return pwd_context.verify(plain_password, hashed_password)


def hash_refresh_token(token: str) -> str:
    """Возвращает SHA-256 хэш refresh-токена."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_agent_token(token: str) -> str:
    """Возвращает SHA-256 хэш agent API token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_invitation_token() -> str:
    """Генерирует «сырой» токен активации для ссылки-приглашения."""
    return secrets.token_urlsafe(32)


def hash_invitation_token(token: str) -> str:
    """Возвращает SHA-256 хэш токена приглашения (в БД храним только хэш)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_password_reset_token() -> str:
    """Генерирует «сырой» токен для ссылки восстановления пароля."""
    return secrets.token_urlsafe(32)


def hash_password_reset_token(token: str) -> str:
    """Возвращает SHA-256 хэш токена сброса пароля (в БД храним только хэш)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_reactivation_token() -> str:
    """Генерирует «сырой» токен для ссылки возврата деактивированного пользователя."""
    return secrets.token_urlsafe(32)


def hash_reactivation_token(token: str) -> str:
    """Возвращает SHA-256 хэш токена возврата (в БД храним только хэш)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _encode_token(subject: int, token_type: str, expires_delta: timedelta) -> str:
    expire_at = datetime.now(UTC) + expires_delta
    payload = {
        "sub": str(subject),
        "type": token_type,
        "exp": int(expire_at.timestamp()),
        "iat": int(datetime.now(UTC).timestamp()),
        # jti делает каждый токен уникальным. Без него два токена одного юзера,
        # выданные в одну секунду (auto-login после активации + вход, двойной
        # refresh, две вкладки), давали одинаковый hash → UniqueViolation на
        # refresh_tokens.token_hash. decode_token jti игнорирует — совместимо.
        "jti": secrets.token_hex(8),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm="HS256")


def create_access_token(user_id: int) -> str:
    """Генерирует короткоживущий access-токен."""
    return _encode_token(user_id, "access", timedelta(minutes=settings.jwt_access_token_expire_minutes))


def create_refresh_token(user_id: int) -> str:
    """Генерирует долгоживущий refresh-токен."""
    return _encode_token(user_id, "refresh", timedelta(days=settings.jwt_refresh_token_expire_days))


def create_2fa_pending_token(user_id: int) -> str:
    """Генерирует короткоживущий токен «пароль принят, ждём код TOTP»."""
    return _encode_token(user_id, TWO_FA_PENDING_TYPE, timedelta(minutes=TWO_FA_PENDING_TTL_MINUTES))


def decode_token(token: str, expected_type: str) -> int:
    """Декодирует JWT и проверяет тип токена."""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        if payload.get("type") != expected_type:
            raise UnauthorizedError("Некорректный тип токена")
        sub = payload.get("sub")
        if not sub:
            raise UnauthorizedError("В токене отсутствует sub")
        return int(sub)
    except (JWTError, ValueError) as exc:
        raise UnauthorizedError("Токен недействителен или истёк") from exc


# ---------------------------------------------------------------------------
# Шифрование секретов «at rest» (Fernet поверх производного от JWT-секрета ключа).
# Тот же приём, что в JiraIntegrationService, вынесен сюда для переиспользования.
# ---------------------------------------------------------------------------


def _fernet():
    from cryptography.fernet import Fernet

    key = base64.urlsafe_b64encode(hashlib.sha256(settings.jwt_secret_key.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_secret(value: str) -> str:
    """Шифрует произвольный секрет для хранения в БД."""
    return _fernet().encrypt(value.encode("utf-8")).decode("utf-8")


def decrypt_secret(value: str) -> str:
    """Расшифровывает секрет, зашифрованный encrypt_secret."""
    return _fernet().decrypt(value.encode("utf-8")).decode("utf-8")


# ---------------------------------------------------------------------------
# TOTP (RFC 6238) — совместим с Google Authenticator / Authy / 1Password и др.
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    """Генерирует случайный base32-секрет TOTP."""
    return pyotp.random_base32()


def verify_totp(secret: str, code: str) -> bool:
    """Проверяет 6-значный код TOTP с допуском на рассинхрон часов ±30с."""
    cleaned = (code or "").replace(" ", "").strip()
    if not cleaned:
        return False
    return pyotp.TOTP(secret).verify(cleaned, valid_window=1)


def totp_provisioning_uri(secret: str, account_name: str) -> str:
    """Строит otpauth://-URI для добавления в приложение-аутентификатор."""
    return pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=TOTP_ISSUER)


def totp_qr_png_data_url(otpauth_uri: str) -> str:
    """Рендерит otpauth-URI в QR-код и возвращает его как data:image/png;base64."""
    img = qrcode.make(otpauth_uri)
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
