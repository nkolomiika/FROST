package inventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Порт backend/tests/test_asset_service.py — паритет поведения AssetService
// (нормализация UUID-путей, разбор raw-request, дедуп эндпоинтов, нормализация
// IP-записей, фильтр списка хостов по origin). Все функции — из пакета inventory.

func nowFn() time.Time { return time.Unix(0, 0) }

// ─────────────────────────── normalize endpoint path ───────────────────────────

// test_normalize_endpoint_path_replaces_uuid_segments
func TestNormalizeEndpointPath_ReplacesUUIDSegments(t *testing.T) {
	got := normalizeEndpointPath("/api/v1/users/550e8400-e29b-41d4-a716-446655440000/orders")
	if got != "/api/v1/users/{UUID}/orders" {
		t.Errorf("normalizeEndpointPath = %q", got)
	}
}

// ─────────────────────────── apply raw request payload ───────────────────────────

// test_apply_raw_request_payload_normalizes_uuid_path
func TestApplyRawRequestPayload_NormalizesUUIDPath(t *testing.T) {
	raw := "GET /api/v1/users/550e8400-e29b-41d4-a716-446655440000?page=1 HTTP/1.1\nHost: demo.local"
	payload := buildEndpointPayload(fullPresent(&EndpointRaw{RequestRaw: strp(raw)}))
	if err := applyRawRequestPayload(payload); err != nil {
		t.Fatalf("applyRaw error: %v", err)
	}
	applyStructuredRequestPayload(payload)
	if getStr(payload, "path") != "/api/v1/users/{UUID}" {
		t.Errorf("path = %q", getStr(payload, "path"))
	}
	qps := getQP(payload)
	if len(qps) != 1 || qps[0].Name != "page" || qps[0].Value == nil || *qps[0].Value != "1" ||
		qps[0].Required || qps[0].Description != nil {
		t.Errorf("query_params = %+v", qps)
	}
}

// test_apply_raw_request_payload_drops_empty_request_raw
func TestApplyRawRequestPayload_DropsEmptyRequestRaw(t *testing.T) {
	payload := map[string]any{"path": "/users", "method": "GET", "request_raw": nil}
	if err := applyRawRequestPayload(payload); err != nil {
		t.Fatalf("applyRaw error: %v", err)
	}
	if _, ok := payload["request_raw"]; ok {
		t.Errorf("request_raw должен быть удалён: %+v", payload)
	}
	if len(payload) != 2 || payload["path"] != "/users" || payload["method"] != "GET" {
		t.Errorf("payload должен остаться {path,method}: %+v", payload)
	}
}

// test_apply_raw_request_payload_parses_non_empty_request_raw
func TestApplyRawRequestPayload_ParsesNonEmptyRequestRaw(t *testing.T) {
	raw := "POST /api/v1/users?role=admin HTTP/1.1\nHost: example.local\nContent-Type: application/json\n\n{\"name\":\"alice\"}"
	payload := buildEndpointPayload(fullPresent(&EndpointRaw{RequestRaw: strp(raw)}))
	if err := applyRawRequestPayload(payload); err != nil {
		t.Fatalf("applyRaw error: %v", err)
	}
	applyStructuredRequestPayload(payload)
	if _, ok := payload["request_raw"]; ok {
		t.Errorf("request_raw должен быть удалён")
	}
	if getStr(payload, "method") != "POST" {
		t.Errorf("method = %q", getStr(payload, "method"))
	}
	if getStr(payload, "path") != "/api/v1/users" {
		t.Errorf("path = %q", getStr(payload, "path"))
	}
	if getStr(payload, "request_content_type") != "application/json" {
		t.Errorf("content_type = %q", getStr(payload, "request_content_type"))
	}
	if getStr(payload, "request_body") != "{\"name\":\"alice\"}" {
		t.Errorf("body = %q", getStr(payload, "request_body"))
	}
	qps := getQP(payload)
	if len(qps) != 1 || qps[0].Name != "role" || qps[0].Value == nil || *qps[0].Value != "admin" {
		t.Errorf("query_params = %+v", qps)
	}
}

// ─────────────────────────── create endpoint dedup ───────────────────────────

// test_create_endpoint_checks_duplicate_by_normalized_uuid_path
func TestCreateEndpoint_ChecksDuplicateByNormalizedUUIDPath(t *testing.T) {
	dup := &Endpoint{ID: 99, HostID: 2, Path: "/api/v1/users/{UUID}", Method: strp("GET"),
		QueryParams: json.RawMessage("[]"), RequestHeaders: json.RawMessage("[]")}
	store := &fakeInvStore{host: &Host{ID: 2}, dupEndpoint: dup}
	svc := NewService(store, nowFn)

	raw := EndpointRaw{
		Present:        map[string]bool{"path": true, "method": true, "query_params": true, "request_headers": true},
		Path:           strp("/api/v1/users/550e8400-e29b-41d4-a716-446655440000"),
		Method:         strp("GET"),
		QueryParams:    &[]QueryParamInput{{Name: "page", Value: strp("1"), Required: false}},
		RequestHeaders: &[]HeaderInput{},
	}
	result, err := svc.CreateEndpoint(context.Background(), 1, 2, raw, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// дедуп ищется по нормализованному UUID-пути
	if store.findDupPath != "/api/v1/users/{UUID}" {
		t.Errorf("FindEndpointDup вызван с path=%q", store.findDupPath)
	}
	// новый эндпоинт не создаётся (upsert в существующий)
	if store.insertCalled {
		t.Errorf("InsertEndpoint не должен вызываться при дубле")
	}
	if !store.updateWasCalled {
		t.Errorf("ожидался upsert (UpdateEndpoint) в существующий эндпоинт")
	}
	if result.ID != 99 {
		t.Errorf("должен вернуться существующий эндпоинт (id 99), получен %d", result.ID)
	}
	// пустые query_params существующего заполняются присланными
	if isEmptyJSON(store.updatedParams.QueryParams) || !strings.Contains(string(store.updatedParams.QueryParams), "page") {
		t.Errorf("query_params должны заполниться: %s", store.updatedParams.QueryParams)
	}
}

// ─────────────────────────── normalize host IP entries ───────────────────────────

// test_normalize_host_ip_entries_deduplicates_and_marks_primary
func TestNormalizeHostIPEntries_DeduplicatesAndMarksPrimary(t *testing.T) {
	entries := normalizeHostIPEntries(strp("10.0.0.2"), []RawIPEntry{
		{IPAddress: strp("10.0.0.1"), Label: strp("mgmt"), IsPrimary: true},
		{IPAddress: strp("10.0.0.2"), Label: strp("public"), IsPrimary: false},
		{IPAddress: strp("10.0.0.1"), Label: strp("duplicate"), IsPrimary: false},
	})
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d (%+v)", len(entries), entries)
	}
	if entries[0].IPAddress != "10.0.0.1" || entries[1].IPAddress != "10.0.0.2" {
		t.Errorf("ips = %+v", entries)
	}
	if entries[0].IsPrimary || !entries[1].IsPrimary {
		t.Errorf("primary должен быть на 10.0.0.2: %+v", entries)
	}
}

// test_normalize_host_ip_entries_keeps_cloudflare_out_of_user_input
func TestNormalizeHostIPEntries_KeepsCloudflareOutOfUserInput(t *testing.T) {
	entries := normalizeHostIPEntries(strp("104.16.0.1"), []RawIPEntry{})
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.IPAddress != "104.16.0.1" || e.Label != nil || !e.IsPrimary {
		t.Errorf("entry = %+v (want {104.16.0.1, nil, primary}); is_cloudflare не входит в пользовательский ввод", e)
	}
}

// ─────────────────────────── list hosts origin filter ───────────────────────────

// test_list_hosts_filters_by_origin — служебные строки IP-фермы прячутся по умолчанию;
// origin="all" отключает фильтр (пустой Origin передаётся в стор).
func TestListHosts_FiltersByOrigin(t *testing.T) {
	cases := []struct {
		origin     string
		wantOrigin string
		wantFilter bool
	}{
		{"host", "host", true},
		{"ip", "ip", true},
		{"all", "", false},
	}
	for _, c := range cases {
		store := &fakeInvStore{}
		svc := NewService(store, nowFn)
		if _, _, err := svc.ListHosts(context.Background(), 1, 1, 20, "", c.origin); err != nil {
			t.Fatalf("origin=%s: %v", c.origin, err)
		}
		got := store.lastListParams.Origin
		if got != c.wantOrigin {
			t.Errorf("origin=%s: store Origin=%q want %q", c.origin, got, c.wantOrigin)
		}
		if (got != "") != c.wantFilter {
			t.Errorf("origin=%s: фильтрация=%v want %v", c.origin, got != "", c.wantFilter)
		}
	}
}
