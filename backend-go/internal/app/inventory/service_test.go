package inventory

import (
	"encoding/json"
	"testing"
)

func strp(s string) *string { return &s }

// ─────────────────────────── IP-нормализация ───────────────────────────

func TestNormalizeHostIPEntries_DedupAndSinglePrimary(t *testing.T) {
	entries := normalizeHostIPEntries(nil, []RawIPEntry{
		{IPAddress: strp("1.1.1.1"), IsPrimary: true},
		{IPAddress: strp("2.2.2.2"), IsPrimary: true}, // второй primary должен погаснуть
		{IPAddress: strp(" 1.1.1.1 ")},                // дубль после trim
		{IPAddress: strp("")},                         // пустой пропускается
	})
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d (%+v)", len(entries), entries)
	}
	if !entries[0].IsPrimary || entries[1].IsPrimary {
		t.Fatalf("exactly the first must be primary: %+v", entries)
	}
	if entries[0].IPAddress != "1.1.1.1" || entries[1].IPAddress != "2.2.2.2" {
		t.Fatalf("unexpected ips: %+v", entries)
	}
}

func TestNormalizeHostIPEntries_PrimaryIPMovesFlag(t *testing.T) {
	entries := normalizeHostIPEntries(strp("2.2.2.2"), []RawIPEntry{
		{IPAddress: strp("1.1.1.1"), IsPrimary: true},
		{IPAddress: strp("2.2.2.2")},
	})
	if entries[0].IsPrimary || !entries[1].IsPrimary {
		t.Fatalf("primary_ip should flip primary to 2.2.2.2: %+v", entries)
	}
}

func TestNormalizeHostIPEntries_PrimaryIPInserted(t *testing.T) {
	entries := normalizeHostIPEntries(strp("9.9.9.9"), []RawIPEntry{
		{IPAddress: strp("1.1.1.1")},
	})
	if len(entries) != 2 || entries[0].IPAddress != "9.9.9.9" || !entries[0].IsPrimary {
		t.Fatalf("primary_ip should be inserted at front as primary: %+v", entries)
	}
	if entries[1].IsPrimary {
		t.Fatalf("second entry must not be primary: %+v", entries)
	}
}

func TestNormalizeHostIPEntries_FirstBecomesPrimaryWhenNoneMarked(t *testing.T) {
	entries := normalizeHostIPEntries(nil, []RawIPEntry{
		{IPAddress: strp("1.1.1.1")},
		{IPAddress: strp("2.2.2.2")},
	})
	if !entries[0].IsPrimary || entries[1].IsPrimary {
		t.Fatalf("first must default to primary: %+v", entries)
	}
}

// ─────────────────────────── path-нормализация ───────────────────────────

func TestNormalizeEndpointPath(t *testing.T) {
	cases := map[string]string{
		"/api//users///1": "/api/users/1",
		"api/users/":      "/api/users",
		"/":               "/",
		"":                "/",
		"/u/550e8400-e29b-41d4-a716-446655440000/x": "/u/{UUID}/x",
		"https://h.example/a/b?x=1":                 "/a/b",
		"/trailing/":                                "/trailing",
	}
	for in, want := range cases {
		if got := normalizeEndpointPath(in); got != want {
			t.Errorf("normalizeEndpointPath(%q)=%q want %q", in, got, want)
		}
	}
}

// ─────────────────────────── raw-request parse/sanitize ───────────────────────────

func TestApplyRawRequestPayload_ParsesAndSanitizes(t *testing.T) {
	raw := "POST /api/users//1//550e8400-e29b-41d4-a716-446655440000?q=1 HTTP/1.1\r\n" +
		"Host: target\r\n" +
		"Cookie: sid=abc\r\n" +
		"Authorization: Bearer secret\r\n" +
		"User-Agent: curl\r\n" +
		"Content-Type: application/json\r\n" +
		"X-Trace: keep\r\n" +
		"\r\n" +
		"{\"a\":1}"
	payload := buildEndpointPayload(fullPresent(&EndpointRaw{RequestRaw: strp(raw)}))
	if err := applyRawRequestPayload(payload); err != nil {
		t.Fatalf("applyRaw error: %v", err)
	}
	applyStructuredRequestPayload(payload)

	if getStr(payload, "method") != "POST" {
		t.Errorf("method = %q", getStr(payload, "method"))
	}
	if getStr(payload, "path") != "/api/users/1/{UUID}" {
		t.Errorf("path = %q", getStr(payload, "path"))
	}
	if getStr(payload, "request_body") != "{\"a\":1}" {
		t.Errorf("body = %q", getStr(payload, "request_body"))
	}
	if getStr(payload, "request_content_type") != "application/json" {
		t.Errorf("content_type = %q", getStr(payload, "request_content_type"))
	}
	qps := getQP(payload)
	if len(qps) != 1 || qps[0].Name != "q" || qps[0].Value == nil || *qps[0].Value != "1" {
		t.Errorf("query_params = %+v", qps)
	}
	hdrs := getHdr(payload)
	// Host/User-Agent/Content-Type сброшены; Authorization/Cookie заменены плейсхолдерами; X-Trace сохранён.
	got := map[string]string{}
	for _, h := range hdrs {
		got[h.Name] = h.Value
	}
	if got["Authorization"] != "{YOUR_CREDENTIALS_HERE}" {
		t.Errorf("Authorization not masked: %+v", hdrs)
	}
	if got["Cookie"] != "{YOUR_TOKENS_HERE}" {
		t.Errorf("Cookie not masked: %+v", hdrs)
	}
	if got["X-Trace"] != "keep" {
		t.Errorf("X-Trace lost: %+v", hdrs)
	}
	if _, ok := got["Host"]; ok {
		t.Errorf("Host must be dropped: %+v", hdrs)
	}
	if _, ok := got["User-Agent"]; ok {
		t.Errorf("User-Agent must be dropped: %+v", hdrs)
	}
	if _, ok := got["Content-Type"]; ok {
		t.Errorf("Content-Type header must be dropped: %+v", hdrs)
	}
}

func TestApplyRawRequestPayload_BodylessMethodStripsBody(t *testing.T) {
	raw := "GET /a HTTP/1.1\r\nContent-Type: application/json\r\n\r\nleftover"
	payload := buildEndpointPayload(fullPresent(&EndpointRaw{RequestRaw: strp(raw)}))
	if err := applyRawRequestPayload(payload); err != nil {
		t.Fatalf("applyRaw error: %v", err)
	}
	if v, ok := payload["request_body"]; !ok || v != nil {
		t.Errorf("GET body must be nil, got %#v", payload["request_body"])
	}
	if v, ok := payload["request_content_type"]; !ok || v != nil {
		t.Errorf("GET content_type must be nil, got %#v", payload["request_content_type"])
	}
}

func TestApplyRawRequestPayload_RejectsBadMethod(t *testing.T) {
	raw := "TRACE /a HTTP/1.1\r\n\r\n"
	payload := buildEndpointPayload(fullPresent(&EndpointRaw{RequestRaw: strp(raw)}))
	if err := applyRawRequestPayload(payload); err == nil {
		t.Fatalf("expected error for unsupported method")
	}
}

// ─────────────────────────── merge-upsert ───────────────────────────

func TestMergeEndpoint_FillsOnlyEmptyFields(t *testing.T) {
	existing := &Endpoint{
		ID:          7,
		Path:        "/a",
		Method:      strp("GET"),
		Description: nil,                   // пусто → заполнится
		QueryParams: json.RawMessage(`[]`), // пусто → заполнится
		RequestBody: strp("keepme"),        // непусто → останется
	}
	payload := buildEndpointPayload(EndpointRaw{
		Present:     map[string]bool{"description": true, "query_params": true, "request_body": true},
		Description: strp("new desc"),
		QueryParams: &[]QueryParamInput{{Name: "x", Value: strp("1")}},
		RequestBody: strp("should-not-win"),
	})
	applyStructuredRequestPayload(payload)
	out := mergeEndpoint(existing, payload)

	if out.ID != 7 || out.Path != "/a" || out.Method == nil || *out.Method != "GET" {
		t.Fatalf("identity fields changed: %+v", out)
	}
	if out.Description == nil || *out.Description != "new desc" {
		t.Errorf("description should be filled: %+v", out.Description)
	}
	if isEmptyJSON(out.QueryParams) {
		t.Errorf("query_params should be filled, got %s", out.QueryParams)
	}
	if out.RequestBody == nil || *out.RequestBody != "keepme" {
		t.Errorf("request_body must be preserved: %+v", out.RequestBody)
	}
}

// fullPresent помечает все ключи эндпоинт-payload присутствующими (как create).
func fullPresent(r *EndpointRaw) EndpointRaw {
	r.Present = map[string]bool{
		"path": true, "method": true, "description": true, "request_raw": true,
		"query_params": true, "request_body": true, "request_content_type": true, "request_headers": true,
	}
	return *r
}
