package recon

import (
	"context"
	"strings"
	"testing"
)

// Регресс: раньше на stormbpmn находились секреты (JWT/generic token) встроенным
// regex-сканером. После включения trufflehog regex ошибочно отключался, и такие
// app-специфичные секреты пропадали. MineJS обязан возвращать их ВСЕГДА, целиком.
func TestMineJS_keepsRegexSecretsFullValue(t *testing.T) {
	jwt := "eyJhbGciOiJIUzUxMiJ9.eyJ1c2VySWQiOjMwNzYxNTQwLCJzdWIiOiJuZXN0In0.K8LDSJ_UTbL8amOER5TTzoA6e7DE"
	text := `var t = "` + jwt + `"; const apiKey = "s3cr3tValue1234567";`

	// Инструменты недоступны в CI → путь fallback, но с полными значениями.
	secrets, _ := MineJS(context.Background(), text, JSMineConfig{Enabled: true, JsluiceBin: "jsluice", TrufflehogBin: "trufflehog"})

	var gotJWT, gotFull bool
	for _, s := range secrets {
		if s.MatchPreview == jwt {
			gotJWT, gotFull = true, true
		}
		if strings.Contains(s.Kind, "jwt") && strings.Contains(s.MatchPreview, "…") {
			t.Errorf("JWT should not be redacted in farm output: %q", s.MatchPreview)
		}
	}
	if !gotJWT {
		t.Fatalf("MineJS dropped the JWT secret; got %d secrets: %+v", len(secrets), secrets)
	}
	if !gotFull {
		t.Errorf("JWT preview not full value")
	}
}
