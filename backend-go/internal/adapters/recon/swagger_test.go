package recon

import "testing"

func TestParseOpenAPIPaths_Swagger2(t *testing.T) {
	body := []byte(`{"swagger":"2.0","basePath":"/api/v1","paths":{"/users":{"get":{},"post":{}},"/health":{"get":{}}}}`)
	hits := parseOpenAPIPaths(body, "https://x.com")
	got := map[string]bool{}
	for _, h := range hits {
		got[h.Method+" "+h.URL] = true
	}
	for _, want := range []string{"GET https://x.com/api/v1/users", "POST https://x.com/api/v1/users", "GET https://x.com/api/v1/health"} {
		if !got[want] {
			t.Errorf("missing %q in %v", want, got)
		}
	}
}

func TestParseOpenAPIPaths_OpenAPI3AbsServer(t *testing.T) {
	body := []byte(`{"openapi":"3.0.0","servers":[{"url":"https://api.x.com/v2"}],"paths":{"/orders":{"get":{}}}}`)
	hits := parseOpenAPIPaths(body, "https://x.com")
	if len(hits) != 1 || hits[0].URL != "https://api.x.com/v2/orders" || hits[0].Method != "GET" {
		t.Fatalf("unexpected hits: %+v", hits)
	}
}

func TestParseOpenAPIPaths_NotASpec(t *testing.T) {
	if hits := parseOpenAPIPaths([]byte(`{"foo":"bar"}`), "https://x.com"); len(hits) != 0 {
		t.Fatalf("expected 0 hits for non-spec, got %v", hits)
	}
}
