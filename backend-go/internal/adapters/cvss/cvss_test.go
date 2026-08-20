package cvss

import (
	"math"
	"testing"
)

// Эталонные значения из Python-пакета `cvss` (референс FIRST.org v4.0).
// Полная сверка (6000 случайных векторов, 0 расхождений) выполнялась вне репозитория.
func TestScoreKnownVectors(t *testing.T) {
	cases := []struct {
		vec  string
		want float64
	}{
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0},
		{"CVSS:4.0/AV:P/AC:H/AT:N/PR:H/UI:P/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A", 7.3},
		{"CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", 2.4},
		{"CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:H/VI:L/VA:L/SC:H/SI:H/SA:H/E:U/CR:H/IR:M/AR:L", 3.6},
		{"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/MSI:S", 9.7},
	}
	for _, c := range cases {
		got, err := Score(c.vec)
		if err != nil {
			t.Fatalf("Score(%s): %v", c.vec, err)
		}
		if math.Abs(got-c.want) > 1e-9 {
			t.Errorf("Score(%s) = %.1f, want %.1f", c.vec, got, c.want)
		}
	}
}

func TestScoreMalformed(t *testing.T) {
	for _, v := range []string{
		"", "CVSS:3.1/AV:N", "CVSS:4.0/AV:N/", "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
		"CVSS:4.0/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", // missing AV (mandatory)
	} {
		if _, err := Score(v); err == nil {
			t.Errorf("expected error for %q", v)
		}
	}
}
