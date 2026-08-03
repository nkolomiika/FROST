from itertools import count as _id_count

_ids = _id_count(1)

import pyotp
import pytest

from app.exceptions import UnauthorizedError
from app.security import (
    TWO_FA_PENDING_TYPE,
    create_2fa_pending_token,
    create_access_token,
    create_refresh_token,
    decode_token,
    decrypt_secret,
    encrypt_secret,
    generate_totp_secret,
    hash_refresh_token,
    totp_provisioning_uri,
    totp_qr_png_data_url,
    verify_totp,
)


def test_access_token_roundtrip_tc_auth_001() -> None:
    user_id = next(_ids)

    token = create_access_token(user_id)
    decoded_id = decode_token(token, expected_type="access")

    assert decoded_id == user_id


def test_refresh_token_roundtrip_tc_auth_006() -> None:
    user_id = next(_ids)

    token = create_refresh_token(user_id)
    decoded_id = decode_token(token, expected_type="refresh")

    assert decoded_id == user_id


def test_decode_token_rejects_wrong_type_tc_auth_010() -> None:
    token = create_refresh_token(next(_ids))

    with pytest.raises(UnauthorizedError, match="Некорректный тип токена"):
        decode_token(token, expected_type="access")


def test_hash_refresh_token_is_deterministic() -> None:
    token = "refresh-token-value"

    digest_1 = hash_refresh_token(token)
    digest_2 = hash_refresh_token(token)

    assert digest_1 == digest_2
    assert len(digest_1) == 64


def test_totp_verifies_current_code_tc_auth_2fa_001() -> None:
    secret = generate_totp_secret()
    current_code = pyotp.TOTP(secret).now()

    assert verify_totp(secret, current_code) is True
    assert verify_totp(secret, "000000") is False
    assert verify_totp(secret, "") is False


def test_totp_accepts_code_with_spaces_tc_auth_2fa_002() -> None:
    secret = generate_totp_secret()
    code = pyotp.TOTP(secret).now()

    spaced = f"{code[:3]} {code[3:]}"
    assert verify_totp(secret, spaced) is True


def test_secret_encryption_roundtrip_tc_auth_2fa_003() -> None:
    secret = generate_totp_secret()

    ciphertext = encrypt_secret(secret)

    assert ciphertext != secret
    assert decrypt_secret(ciphertext) == secret


def test_pending_2fa_token_roundtrip_tc_auth_2fa_004() -> None:
    token = create_2fa_pending_token(42)

    assert decode_token(token, expected_type=TWO_FA_PENDING_TYPE) == 42
    with pytest.raises(UnauthorizedError):
        decode_token(token, expected_type="access")


def test_provisioning_uri_and_qr_tc_auth_2fa_005() -> None:
    secret = generate_totp_secret()

    uri = totp_provisioning_uri(secret, "alice")
    assert uri.startswith("otpauth://totp/")
    assert "issuer=STORM" in uri
    assert secret in uri

    qr = totp_qr_png_data_url(uri)
    assert qr.startswith("data:image/png;base64,")
