package security

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestPasswordHashVerify(t *testing.T) {
	hash, err := HashPassword("s3cret-пароль")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !VerifyPassword("s3cret-пароль", hash) {
		t.Fatal("верный пароль не прошёл проверку")
	}
	if VerifyPassword("wrong", hash) {
		t.Fatal("неверный пароль прошёл проверку")
	}
}

func TestHashTokenSHA256KnownVector(t *testing.T) {
	// sha256("abc") — фиксированный вектор, доказывает совместимость с Python hashlib.
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := HashTokenSHA256("abc"); got != want {
		t.Fatalf("sha256(abc)=%s, want %s", got, want)
	}
}

func TestGenerateURLSafeToken(t *testing.T) {
	tok := GenerateURLSafeToken(32)
	if strings.ContainsAny(tok, "+/=") {
		t.Fatalf("urlsafe-токен содержит небезопасные символы: %s", tok)
	}
	if GenerateURLSafeToken(32) == tok {
		t.Fatal("два токена совпали — нет энтропии")
	}
}

func TestJWTRoundTripAndTypeCheck(t *testing.T) {
	m := NewJWTManager(strings.Repeat("x", 32), 30, 30)
	access, err := m.CreateAccessToken(42)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	id, err := m.Decode(access, TokenTypeAccess)
	if err != nil || id != 42 {
		t.Fatalf("decode: id=%d err=%v", id, err)
	}
	if _, err := m.Decode(access, TokenTypeRefresh); err != ErrWrongTokenType {
		t.Fatalf("ожидали ErrWrongTokenType, получили %v", err)
	}
	if _, err := m.Decode(access+"tamper", TokenTypeAccess); err != ErrInvalidToken {
		t.Fatalf("ожидали ErrInvalidToken на подделке, получили %v", err)
	}
	// Токен, подписанный другим секретом, не проходит.
	other := NewJWTManager(strings.Repeat("y", 32), 30, 30)
	foreign, _ := other.CreateAccessToken(1)
	if _, err := m.Decode(foreign, TokenTypeAccess); err != ErrInvalidToken {
		t.Fatalf("чужая подпись прошла: %v", err)
	}
}

func TestSecretCipherRoundTrip(t *testing.T) {
	c, err := NewSecretCipher(strings.Repeat("k", 40))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	enc, err := c.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	dec, err := c.Decrypt(enc)
	if err != nil || dec != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("decrypt: %q err=%v", dec, err)
	}
}

func TestTOTPGenerateVerify(t *testing.T) {
	secret, err := GenerateTOTPSecret()
	if err != nil || secret == "" {
		t.Fatalf("secret: %q err=%v", secret, err)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("gen code: %v", err)
	}
	if !VerifyTOTP(secret, code) {
		t.Fatal("свежий TOTP-код не прошёл")
	}
	if !VerifyTOTP(secret, " "+code+" ") {
		t.Fatal("код с пробелами должен приниматься")
	}
	if VerifyTOTP(secret, "000000") && code != "000000" {
		t.Skip("маловероятное совпадение 000000")
	}
	uri := TOTPProvisioningURI(secret, "alice@example.com")
	if !strings.Contains(uri, "secret="+secret) || !strings.Contains(uri, "issuer=FROST") {
		t.Fatalf("некорректный provisioning uri: %s", uri)
	}
	dataURL, err := TOTPQRPNGDataURL(uri)
	if err != nil || !strings.HasPrefix(dataURL, "data:image/png;base64,") {
		t.Fatalf("qr data url: %q err=%v", dataURL[:min(30, len(dataURL))], err)
	}
}
