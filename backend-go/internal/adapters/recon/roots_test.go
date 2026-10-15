package recon

import "testing"

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"apuat9.prudential.com.hk": "prudential.com.hk",
		"www.acme.com":             "acme.com",
		"acme.com":                 "acme.com",
		"a.b.c.example.co.uk":      "example.co.uk",
		"pruconnect.net":           "pruconnect.net",
		"api.prubsn.com.my":        "prubsn.com.my",
		"foo":                      "foo",
		"1.2.3.4":                  "1.2.3.4", // IP-литерал — как есть
	}
	for in, want := range cases {
		if got := RegistrableDomain(in); got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWithRegistrableRoots(t *testing.T) {
	in := []*ParsedTarget{
		{Hostname: "www.acme.com", ExplicitPorts: map[int]string{}},
		{Hostname: "mail.acme.com", ExplicitPorts: map[int]string{}},
		{Hostname: "acme.com", ExplicitPorts: map[int]string{}}, // корень уже есть — не дублируем
		{Hostname: "1.2.3.4", IsIP: true, ExplicitPorts: map[int]string{}},
	}
	out := WithRegistrableRoots(in)
	names := map[string]int{}
	for _, t := range out {
		names[t.Hostname]++
	}
	if names["acme.com"] != 1 {
		t.Fatalf("acme.com count = %d, want 1 (no duplicate root)", names["acme.com"])
	}
	if len(out) != 4 {
		t.Fatalf("len(out) = %d, want 4 (root already present, IP skipped)", len(out))
	}
}
