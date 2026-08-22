package recon

import "testing"

func TestSafeArg(t *testing.T) {
	good := []string{"example.com", "api.sub.example.com", "10.0.0.1", "a_b-c.example.com"}
	for _, g := range good {
		if !safeArg(g) {
			t.Errorf("safeArg(%q) = false, want true", g)
		}
	}
	bad := []string{
		"",             // пусто
		"-d",           // ведущий дефис (флаг)
		"--flag",       // длинный флаг
		"-oOUT",        // подмена вывода
		"a b",          // пробел
		"a\tb",         // таб
		"a\nb",         // перевод строки
		"host\x00null", // управляющий символ
	}
	for _, b := range bad {
		if safeArg(b) {
			t.Errorf("safeArg(%q) = true, want false (flag-injection guard)", b)
		}
	}
	// safeHost — псевдоним safeArg.
	if safeHost("-x") || !safeHost("example.com") {
		t.Fatal("safeHost mismatch with safeArg")
	}
}
