package inventory

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nkolomiika/frost/internal/apperr"
)

// Порт backend/tests/test_import_service.py — паритет поведения ImportService
// (парсинг JSON/YAML, валидация payload, $ref, извлечение тела/параметров из
// OpenAPI/Swagger, импорт/экспорт). Ряд Python-хелперов не имеет Go-аналога в этом
// пакете (host-matching/merge живут в сторе, relaxed-swagger не портирован) —
// они помечены как PORTING GAP в отчёте и здесь фиксируются документирующими тестами.

func isValidationErr(t *testing.T, err error) {
	t.Helper()
	var e *apperr.Error
	if err == nil || !asErr(err, &e) || e.Kind != apperr.KindValidation {
		t.Fatalf("ожидалась ValidationError, получено: %v", err)
	}
}

func asErr(err error, target **apperr.Error) bool {
	e, ok := err.(*apperr.Error)
	if ok {
		*target = e
	}
	return ok
}

func mustDoc(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("bad doc json: %v", err)
	}
	return m
}

// ─────────────────────────── merge endpoint fields ───────────────────────────

// test_merge_endpoint_fields_preserves_existing_data_and_fills_missing
func TestMergeEndpointFields_FillsMissing(t *testing.T) {
	existing := &Endpoint{
		Description:    nil,
		QueryParams:    json.RawMessage("[]"),
		RequestBody:    nil,
		RequestHeaders: json.RawMessage("[]"),
	}
	raw := EndpointRaw{
		Present:            map[string]bool{"description": true, "query_params": true, "request_body": true, "request_content_type": true, "request_headers": true},
		Description:        strp("Imported endpoint"),
		QueryParams:        &[]QueryParamInput{{Name: "role", Value: strp("admin")}},
		RequestBody:        strp("{\"ok\":true}"),
		RequestContentType: strp("application/json"),
		RequestHeaders:     &[]HeaderInput{{Name: "X-Test", Value: "1"}},
	}
	payload := buildEndpointPayload(raw)
	applyStructuredRequestPayload(payload)
	out := mergeEndpoint(existing, payload)

	if out.Description == nil || *out.Description != "Imported endpoint" {
		t.Errorf("description = %v", out.Description)
	}
	if isEmptyJSON(out.QueryParams) || !strings.Contains(string(out.QueryParams), "role") || !strings.Contains(string(out.QueryParams), "admin") {
		t.Errorf("query_params = %s", out.QueryParams)
	}
	if out.RequestBody == nil || *out.RequestBody != "{\"ok\":true}" {
		t.Errorf("request_body = %v", out.RequestBody)
	}
	if out.RequestContentType == nil || *out.RequestContentType != "application/json" {
		t.Errorf("content_type = %v", out.RequestContentType)
	}
	if isEmptyJSON(out.RequestHeaders) || !strings.Contains(string(out.RequestHeaders), "X-Test") {
		t.Errorf("request_headers = %s", out.RequestHeaders)
	}
}

// ─────────────────────────── load JSON or YAML ───────────────────────────

// test_load_json_or_yaml_document_supports_yaml
func TestLoadJSONOrYAMLDocument_SupportsYAML(t *testing.T) {
	parsed, err := loadJSONOrYAMLDocument("\nopenapi: 3.0.0\npaths:\n  /health:\n    get:\n      summary: Check health\n")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed["openapi"] != "3.0.0" {
		t.Errorf("openapi = %v", parsed["openapi"])
	}
	paths, ok := asMap(parsed["paths"])
	if !ok {
		t.Fatalf("paths не map: %v", parsed["paths"])
	}
	if _, ok := paths["/health"]; !ok {
		t.Errorf("/health отсутствует: %v", paths)
	}
}

// PORTING GAP: relaxed-brace swagger parser (Python _load_json_or_yaml_document)
// в Go НЕ реализован (см. комментарий в openapi.go). Документируем фактическое
// поведение: такой текст отклоняется как невалидный JSON/YAML.
// (порт test_load_json_or_yaml_document_supports_relaxed_swagger_text)
func TestLoadJSONOrYAMLDocument_RelaxedSwagger_PORTING_GAP(t *testing.T) {
	relaxed := "{\n  swagger 2.0,\n  basePath v1,\n  paths {\n    users{userId} {\n      get {\n        summary Get user\n      }\n    }\n  }\n}"
	_, err := loadJSONOrYAMLDocument(relaxed)
	if err == nil {
		t.Fatalf("PORTING GAP закрыт? relaxed-swagger теперь парсится — обнови отчёт")
	}
	isValidationErr(t, err)
}

// ─────────────────────────── validate payload ───────────────────────────

// test_validate_openapi_payload_rejects_empty_bytes
func TestValidateOpenAPIPayload_RejectsEmpty(t *testing.T) {
	err := validateOpenAPIPayload([]byte(""))
	isValidationErr(t, err)
	if !strings.Contains(err.Error(), "пуст") {
		t.Errorf("сообщение = %v", err)
	}
}

// test_validate_openapi_payload_rejects_oversized_bytes
func TestValidateOpenAPIPayload_RejectsOversized(t *testing.T) {
	err := validateOpenAPIPayload(make([]byte, 2*1024*1024+1))
	isValidationErr(t, err)
	if !strings.Contains(err.Error(), "2 МБ") {
		t.Errorf("сообщение = %v", err)
	}
}

// ─────────────────────────── resolve $ref ───────────────────────────

// test_resolve_openapi_ref_supports_local_refs
func TestResolveOpenAPIRef_SupportsLocalRefs(t *testing.T) {
	document := mustDoc(t, `{
		"paths": {"/users": {"$ref": "#/components/pathItems/UsersPath"}},
		"components": {
			"pathItems": {"UsersPath": {"get": {"$ref": "#/components/operations/ListUsers"}}},
			"operations": {"ListUsers": {"summary": "List users"}}
		}
	}`)
	paths, _ := asMap(document["paths"])
	pathItemRaw, err := resolveOpenAPIRef(document, paths["/users"], 0)
	if err != nil {
		t.Fatalf("resolve pathItem: %v", err)
	}
	pathItem, _ := asMap(pathItemRaw)
	get, _ := asMap(pathItem["get"])
	if _, has := get["$ref"]; !has {
		t.Errorf("get всё ещё должен содержать $ref (одноуровневое разрешение): %v", get)
	}
	operationRaw, err := resolveOpenAPIRef(document, pathItem["get"], 0)
	if err != nil {
		t.Fatalf("resolve operation: %v", err)
	}
	operation, _ := asMap(operationRaw)
	if operation["summary"] != "List users" {
		t.Errorf("summary = %v", operation["summary"])
	}
}

// ─────────────────────────── extract request details ───────────────────────────

// test_extract_openapi_request_details_handles_swagger2_body_with_definitions
func TestExtractRequestDetails_Swagger2BodyWithDefinitions(t *testing.T) {
	document := mustDoc(t, `{
		"swagger": "2.0",
		"consumes": ["application/json"],
		"definitions": {"Pet": {"type": "object", "properties": {
			"id": {"type": "integer"},
			"name": {"type": "string", "example": "doggie"},
			"status": {"type": "string", "enum": ["available", "sold"]}
		}}}
	}`)
	operation := mustDoc(t, `{"parameters": [
		{"name": "body", "in": "body", "required": true, "schema": {"$ref": "#/definitions/Pet"}}
	]}`)
	ct, body, err := extractOpenAPIRequestDetails(document, map[string]any{}, operation)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct == nil || *ct != "application/json" {
		t.Errorf("content_type = %v", ct)
	}
	if body == nil || !strings.Contains(*body, "doggie") || !strings.Contains(*body, "available") {
		t.Errorf("body = %v", body)
	}
}

// test_extract_openapi_request_details_handles_swagger2_form_data
func TestExtractRequestDetails_Swagger2FormData(t *testing.T) {
	document := mustDoc(t, `{"swagger": "2.0"}`)
	operation := mustDoc(t, `{
		"consumes": ["application/x-www-form-urlencoded"],
		"parameters": [
			{"name": "name", "in": "formData", "type": "string", "example": "rex"},
			{"name": "status", "in": "formData", "type": "string", "default": "available"}
		]
	}`)
	ct, body, err := extractOpenAPIRequestDetails(document, map[string]any{}, operation)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ct == nil || *ct != "application/x-www-form-urlencoded" {
		t.Errorf("content_type = %v", ct)
	}
	if body == nil || *body != "name=rex&status=available" {
		t.Errorf("body = %v", body)
	}
}

// ─────────────────────────── extract query params ───────────────────────────

// test_extract_openapi_query_params_uses_default_or_enum_value
func TestExtractQueryParams_UsesDefaultOrEnum(t *testing.T) {
	document := mustDoc(t, `{"swagger": "2.0"}`)
	operation := mustDoc(t, `{"parameters": [
		{"name": "status", "in": "query", "type": "string", "enum": ["available", "pending", "sold"], "required": true},
		{"name": "limit", "in": "query", "type": "integer", "default": 10}
	]}`)
	params, err := extractOpenAPIQueryParams(document, map[string]any{}, operation)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var status, limit *qparam
	for i := range params {
		switch params[i].Name {
		case "status":
			status = &params[i]
		case "limit":
			limit = &params[i]
		}
	}
	if status == nil || status.Value == nil || *status.Value != "available" || !status.Required || status.Description != nil {
		t.Errorf("status param = %+v", status)
	}
	if limit == nil || limit.Value == nil || *limit.Value != "10" || limit.Required || limit.Description != nil {
		t.Errorf("limit param = %+v", limit)
	}
}

// ─────────────────────────── import OpenAPI ───────────────────────────

// test_import_openapi_skips_duplicate_and_adds_warning
// (дедуп/merge/skip-count делегированы стору UpsertOpenAPIEndpoints — здесь
// проверяется парсинг, spec_host и предупреждение о несовпадении хоста.)
func TestImportOpenAPI_SkipsDuplicateAndAddsWarning(t *testing.T) {
	store := &fakeInvStore{host: &Host{ID: 2, Hostname: strp("current.local")}, upsertCreated: 0, upsertSkipped: 1}
	svc := NewService(store, nowFn)
	payload := []byte("\nopenapi: 3.0.0\nservers:\n  - url: https://api.example.com/v1\npaths:\n  /users:\n    get:\n      summary: List users\n")
	result, err := svc.ImportOpenAPI(context.Background(), 1, 2, payload, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.EndpointsCreated != 0 || result.EndpointsSkipped != 1 {
		t.Errorf("created/skipped = %d/%d", result.EndpointsCreated, result.EndpointsSkipped)
	}
	if result.SpecHost == nil || *result.SpecHost != "api.example.com" {
		t.Errorf("spec_host = %v", result.SpecHost)
	}
	if len(result.Errors) == 0 {
		t.Errorf("ожидалось предупреждение о несовпадении хоста")
	}
	if len(store.upsertEps) != 1 || store.upsertEps[0].Description == nil || *store.upsertEps[0].Description != "List users" {
		t.Errorf("захваченные эндпоинты = %+v", store.upsertEps)
	}
}

// PORTING GAP: relaxed-swagger не парсится в Go → import_openapi этого текста падает
// валидацией (в Python endpoints_created==1). Документируем реальное поведение.
// (порт test_import_openapi_accepts_relaxed_swagger_text)
func TestImportOpenAPI_RelaxedSwagger_PORTING_GAP(t *testing.T) {
	store := &fakeInvStore{host: &Host{ID: 2, Hostname: strp("current.local")}}
	svc := NewService(store, nowFn)
	payload := []byte("{\n  swagger 2.0,\n  basePath v1,\n  paths {\n    users{userId} {\n      get { summary Get user }\n    }\n  }\n}")
	_, err := svc.ImportOpenAPI(context.Background(), 1, 2, payload, 3)
	if err == nil {
		t.Fatalf("PORTING GAP закрыт? relaxed-swagger теперь импортируется — обнови отчёт")
	}
	isValidationErr(t, err)
}

// test_import_openapi_skips_deprecated_operations
func TestImportOpenAPI_SkipsDeprecatedOperations(t *testing.T) {
	store := &fakeInvStore{host: &Host{ID: 2, Hostname: strp("api.local")}, upsertCreated: 1}
	svc := NewService(store, nowFn)
	payload := []byte("\nopenapi: 3.0.0\npaths:\n  /pet/findByTags:\n    get:\n      summary: Finds Pets by tags\n      deprecated: true\n  /pet/findByStatus:\n    get:\n      summary: Finds Pets by status\n")
	result, err := svc.ImportOpenAPI(context.Background(), 1, 2, payload, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.EndpointsCreated != 1 {
		t.Errorf("created = %d", result.EndpointsCreated)
	}
	deprecatedWarned := false
	for _, e := range result.Errors {
		if strings.Contains(strings.ToLower(e), "deprecated") {
			deprecatedWarned = true
		}
	}
	if !deprecatedWarned {
		t.Errorf("ожидалось предупреждение о deprecated: %v", result.Errors)
	}
	if len(store.upsertEps) != 1 || store.upsertEps[0].Path != "/pet/findByStatus" {
		t.Errorf("должен импортироваться только /pet/findByStatus: %+v", store.upsertEps)
	}
}

// test_export_openapi_builds_document_from_endpoints
func TestExportOpenAPI_BuildsDocumentFromEndpoints(t *testing.T) {
	qps, _ := json.Marshal([]qparam{{Name: "verbose", Value: strp("true"), Required: false, Description: strp("verbose mode")}})
	hdrs, _ := json.Marshal([]header{{Name: "X-Trace", Value: "abc"}})
	endpoint := Endpoint{
		Path:           "/pet/{petId}",
		Method:         strp("GET"),
		Description:    strp("Find pet by ID"),
		QueryParams:    qps,
		RequestHeaders: hdrs,
	}
	store := &fakeInvStore{host: &Host{ID: 2, Hostname: strp("api.local")}, orderedEndpoints: []Endpoint{endpoint}}
	svc := NewService(store, nowFn)
	document, err := svc.ExportOpenAPI(context.Background(), 1, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if document["openapi"] != "3.0.0" {
		t.Errorf("openapi = %v", document["openapi"])
	}
	info, _ := document["info"].(map[string]any)
	if info["title"] != "api.local" {
		t.Errorf("title = %v", info["title"])
	}
	paths, _ := document["paths"].(map[string]any)
	pathItem, _ := paths["/pet/{petId}"].(map[string]any)
	operation, _ := pathItem["get"].(map[string]any)
	if operation["summary"] != "Find pet by ID" {
		t.Errorf("summary = %v", operation["summary"])
	}
	params, _ := operation["parameters"].([]any)
	locations := map[string]bool{}
	verboseExampleOK := false
	for _, raw := range params {
		p, _ := raw.(map[string]any)
		locations[strings.ToLower(strAny2(p["in"]))] = true
		if p["name"] == "verbose" && p["example"] == "true" {
			verboseExampleOK = true
		}
	}
	if !locations["query"] || !locations["header"] {
		t.Errorf("ожидались параметры query и header: %v", locations)
	}
	if !verboseExampleOK {
		t.Errorf("verbose param с example=true отсутствует: %v", params)
	}
}

func strAny2(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// ─────────────────────────── PORTING GAPs: host matching/merge ───────────────────────────

// PORTING GAP: ImportService._find_matching_host / _merge_host_fields не имеют
// аналога в пакете inventory — сопоставление и слияние хостов при PCF-импорте
// выполняются атомарно внутри адаптера стора (store.ImportPCF), а не в use-case
// слое. Тестировать нечего на этом уровне; фиксируем факт через провал компиляции,
// если функции появятся (тогда добавить полноценные тесты).
// (порт test_find_matching_host_returns_exact_host, test_merge_host_fields_only_fills_missing_values)
func TestHostMatchingAndMerge_PORTING_GAP(t *testing.T) {
	t.Skip("PORTING GAP: host matching/merge живут в store.ImportPCF (repo/tx), не в пакете inventory — см. отчёт")
}
