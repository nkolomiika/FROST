package config

import (
	"strings"
	"testing"
)

// Порт backend/tests/test_schemas.py::test_settings_reject_too_short_jwt_secret —
// секрет короче 32 символов должен отклоняться валидацией конфига.
func TestValidateRejectsShortJWTSecret(t *testing.T) {
	c := &Config{JWTSecretKey: strings.Repeat("a", 31)}
	if err := c.validate(); err == nil {
		t.Fatal("31-char JWT secret must be rejected")
	}
	c.JWTSecretKey = strings.Repeat("a", 32)
	if err := c.validate(); err != nil {
		t.Fatalf("32-char JWT secret must pass: %v", err)
	}
}

// Normalize: SQLAlchemy-URL → postgres:// (понятный pgx).
func TestNormalizeRewritesDatabaseURL(t *testing.T) {
	for _, in := range []string{
		"postgresql+asyncpg://u:p@db:5432/frost",
		"postgresql://u:p@db:5432/frost",
	} {
		c := &Config{DatabaseURL: in}
		c.Normalize()
		if !strings.HasPrefix(c.DatabaseURL, "postgres://") {
			t.Errorf("Normalize(%q) = %q, want postgres:// prefix", in, c.DatabaseURL)
		}
	}
}

// CSRFOrigins/CORSOrigins: CSV → срез с обрезкой пустых/пробелов.
func TestSplitCSVTrimsAndDropsEmpty(t *testing.T) {
	c := &Config{CSRFAllowedOrigins: " a , ,b ,"}
	got := c.CSRFOrigins()
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("CSRFOrigins = %#v", got)
	}
}
