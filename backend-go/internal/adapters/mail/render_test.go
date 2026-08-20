package mail

import (
	"strings"
	"testing"
)

func TestRenderTemplates(t *testing.T) {
	cases := []struct {
		tmpl    string
		payload map[string]any
		wantTxt string
		wantURL string
	}{
		{"password_reset", map[string]any{"username": "Ivan", "reset_url": "https://app/reset-password?token=abc", "expire_hours": float64(2)}, "восстановление пароля", "https://app/reset-password?token=abc"},
		{"invitation", map[string]any{"username": "Ivan", "activation_url": "https://app/activate?token=xyz"}, "пригласили", "https://app/activate?token=xyz"},
		{"reactivation", map[string]any{"username": "Ivan", "reactivate_url": "https://app/reactivate?token=q", "expire_hours": float64(24)}, "возвращением", "https://app/reactivate?token=q"},
		{"temporary_password", map[string]any{"username": "Ivan", "temporary_password": "T3mp!pass"}, "Временный пароль", "T3mp!pass"},
	}
	for _, c := range cases {
		r, err := Render(c.tmpl, c.payload)
		if err != nil {
			t.Fatalf("%s: %v", c.tmpl, err)
		}
		if !strings.Contains(strings.ToLower(r.Text), strings.ToLower(c.wantTxt)) {
			t.Errorf("%s text missing %q: %s", c.tmpl, c.wantTxt, r.Text)
		}
		if !strings.Contains(r.HTML, c.wantURL) || !strings.Contains(r.Text, c.wantURL) {
			t.Errorf("%s missing url/token %q", c.tmpl, c.wantURL)
		}
		if !strings.Contains(r.HTML, "FROST") {
			t.Errorf("%s html missing brand", c.tmpl)
		}
	}
	if _, err := Render("nope", nil); err == nil {
		t.Errorf("unknown template should error")
	}
}
