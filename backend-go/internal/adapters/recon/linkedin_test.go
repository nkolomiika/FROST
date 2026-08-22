package recon

import (
	"reflect"
	"testing"
)

func TestParseLinkedInName(t *testing.T) {
	cases := []struct {
		title            string
		wantFirst, wantL string
		ok               bool
	}{
		{"John Doe - Senior Engineer - Acme | LinkedIn", "John", "Doe", true},
		{"Jane Smith – Product Manager | LinkedIn", "Jane", "Smith", true},
		{"María González - Diseñadora", "María", "González", true},
		{"Bob O'Brien - CTO", "Bob", "O'Brien", true},
		{"Anna-Lena Fischer - HR", "Anna-Lena", "Fischer", true},
		{"LinkedIn", "", "", false},                 // не имя
		{"Top 10 Engineers 2024 - Blog", "", "", false}, // цифры → мусор
		{"Singleword", "", "", false},                // один токен
	}
	for _, c := range cases {
		p, ok := parseLinkedInName(c.title)
		if ok != c.ok {
			t.Fatalf("%q: ok=%v want %v", c.title, ok, c.ok)
		}
		if ok && (p.First != c.wantFirst || p.Last != c.wantL) {
			t.Fatalf("%q: got %s/%s want %s/%s", c.title, p.First, p.Last, c.wantFirst, c.wantL)
		}
	}
}

func TestParseLinkedInResults(t *testing.T) {
	html := `
<div><a class="result__a" href="https://linkedin.com/in/johndoe">John <b>Doe</b> - CEO - Acme | LinkedIn</a></div>
<div><a class="result__a" href="https://linkedin.com/in/janes">Jane Smith - Engineer | LinkedIn</a></div>
<div><a class="result__a" href="https://example.com">Some Random Page 2024</a></div>`
	people := parseLinkedInResults(html)
	if len(people) != 2 {
		t.Fatalf("want 2 people, got %d (%+v)", len(people), people)
	}
	if people[0].First != "John" || people[0].Last != "Doe" {
		t.Fatalf("first person wrong: %+v", people[0])
	}
}

func TestGenerateEmails(t *testing.T) {
	people := []LinkedInPerson{{First: "John", Last: "Doe"}}
	got := GenerateEmails(people, []string{"acme.com"}, 100)
	want := []string{"john.doe@acme.com", "jdoe@acme.com", "johndoe@acme.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Без домена — пусто (человек остаётся account-находкой, но почт не строим).
	if em := GenerateEmails(people, nil, 100); em != nil {
		t.Fatalf("expected nil without domains, got %v", em)
	}
	// Нелатинское имя схлопывается → пропускается генерацией.
	if em := GenerateEmails([]LinkedInPerson{{First: "Иван", Last: "Петров"}}, []string{"x.com"}, 100); em != nil {
		t.Fatalf("expected nil for non-latin, got %v", em)
	}
	// Потолок соблюдается.
	if em := GenerateEmails(people, []string{"acme.com"}, 2); len(em) != 2 {
		t.Fatalf("cap not honored: %v", em)
	}
}
