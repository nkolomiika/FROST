package security

import (
	"strings"
	"testing"
)

// Порт недостающих кейсов backend/tests/test_security.py. Access-roundtrip,
// wrong-type, tamper и TOTP current/spaces/uri/qr уже покрыты в security_test.go
// (TestJWTRoundTripAndTypeCheck, TestTOTPGenerateVerify); здесь добиты остальные.

// test_refresh_token_roundtrip_tc_auth_006: refresh-токен декодируется обратно в id.
func TestRefreshTokenRoundTrip(t *testing.T) {
	m := NewJWTManager(strings.Repeat("x", 32), 30, 30)
	tok, err := m.CreateRefreshToken(7)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id, err := m.Decode(tok, TokenTypeRefresh)
	if err != nil || id != 7 {
		t.Fatalf("decode refresh: id=%d err=%v", id, err)
	}
}

// test_pending_2fa_token_roundtrip_tc_auth_2fa_004: 2fa-pending декодируется как
// свой тип и отвергается при ожидании access.
func TestPending2FATokenRoundTrip(t *testing.T) {
	m := NewJWTManager(strings.Repeat("x", 32), 30, 30)
	tok, err := m.Create2FAPendingToken(42)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id, err := m.Decode(tok, TokenType2FAPending)
	if err != nil || id != 42 {
		t.Fatalf("decode 2fa_pending: id=%d err=%v", id, err)
	}
	if _, err := m.Decode(tok, TokenTypeAccess); err != ErrWrongTokenType {
		t.Fatalf("expected ErrWrongTokenType decoding 2fa token as access, got %v", err)
	}
}

// test_totp_verifies_current_code_tc_auth_2fa_001 (доводка): пустой и заведомо
// неверный код не проходят проверку.
func TestVerifyTOTPRejectsBadCodes(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("secret: %v", err)
	}
	if VerifyTOTP(secret, "") {
		t.Fatal("empty code must not verify")
	}
	if VerifyTOTP(secret, "000000") {
		t.Fatal("000000 must not verify against a fresh secret")
	}
}
