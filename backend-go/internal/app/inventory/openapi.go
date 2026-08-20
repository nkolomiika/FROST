package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	yaml "github.com/oasdiff/yaml3"

	"github.com/nkolomiika/frost/internal/apperr"
)

const (
	maxOpenAPIImportBytes = 2 * 1024 * 1024
	maxOpenAPIPaths       = 2000
)

var reHTTPScheme = regexp.MustCompile(`(?i)^https?://`)

// ─────────────────────────── import OpenAPI ───────────────────────────

// ImportOpenAPI импортирует OpenAPI/Swagger в endpoint-структуру хоста (upsert,
// атомарно). Порт ImportService.import_openapi.
func (s *Service) ImportOpenAPI(ctx context.Context, projectID, hostID int32, payload []byte, actorID int32) (*OpenAPIImportResult, error) {
	host, err := s.getHost(ctx, projectID, hostID)
	if err != nil {
		return nil, err
	}
	if err := validateOpenAPIPayload(payload); err != nil {
		return nil, err
	}
	rawText, err := decodeTextPayload(payload)
	if err != nil {
		return nil, err
	}
	document, err := loadJSONOrYAMLDocument(rawText)
	if err != nil {
		return nil, err
	}
	paths, ok := asMap(document["paths"])
	if !ok || len(paths) == 0 {
		return nil, apperr.Validation("В Swagger/OpenAPI документе отсутствует объект paths")
	}
	if len(paths) > maxOpenAPIPaths {
		return nil, apperr.Validation("Swagger/OpenAPI документ содержит слишком много paths для импорта")
	}

	specHost := extractOpenAPIHost(document)
	result := &OpenAPIImportResult{HostID: host.ID, SpecHost: specHost, Errors: []string{}}

	currentTargets := map[string]bool{}
	for _, v := range []*string{host.Hostname, host.IPAddress} {
		if v != nil && *v != "" {
			currentTargets[strings.ToLower(*v)] = true
		}
	}
	if specHost != nil && len(currentTargets) > 0 && !currentTargets[strings.ToLower(*specHost)] {
		target := ""
		if host.Hostname != nil && *host.Hostname != "" {
			target = *host.Hostname
		} else if host.IPAddress != nil {
			target = *host.IPAddress
		}
		result.Errors = append(result.Errors, fmt.Sprintf(
			"В спецификации указан host '%s', но импорт выполнен в текущий хост '%s'.", *specHost, target))
	}

	supported := map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true, "options": true}
	prefix := extractPathPrefix(document)
	eps := []EndpointImport{}

	for pathValue, rawPathItem := range paths {
		if strings.TrimSpace(pathValue) == "" {
			continue
		}
		resolved, err := resolveOpenAPIRef(document, rawPathItem, 0)
		if err != nil {
			return nil, err
		}
		pathItem, ok := asMap(resolved)
		if !ok {
			result.Errors = append(result.Errors, fmt.Sprintf("Раздел paths['%s'] имеет некорректную структуру и был пропущен.", pathValue))
			continue
		}
		for rawMethodName, rawOperation := range pathItem {
			methodName := strings.ToLower(rawMethodName)
			if methodName == "parameters" || strings.HasPrefix(methodName, "x-") {
				continue
			}
			if !supported[methodName] {
				result.Errors = append(result.Errors, fmt.Sprintf("Метод '%s' для '%s' не поддерживается и был пропущен.", rawMethodName, pathValue))
				continue
			}
			resolvedOp, err := resolveOpenAPIRef(document, rawOperation, 0)
			if err != nil {
				return nil, err
			}
			operation, ok := asMap(resolvedOp)
			if !ok {
				result.Errors = append(result.Errors, fmt.Sprintf("Операция '%s' для '%s' имеет некорректную структуру.", rawMethodName, pathValue))
				continue
			}
			if truthy(operation["deprecated"]) {
				result.Errors = append(result.Errors, fmt.Sprintf(
					"Операция '%s %s' помечена как deprecated и была пропущена.", strings.ToUpper(rawMethodName), pathValue))
				continue
			}
			contentType, body, err := extractOpenAPIRequestDetails(document, pathItem, operation)
			if err != nil {
				return nil, err
			}
			qps, err := extractOpenAPIQueryParams(document, pathItem, operation)
			if err != nil {
				return nil, err
			}
			descParts := []string{}
			if summary := strings.TrimSpace(asStr(operation["summary"])); summary != "" {
				descParts = append(descParts, summary)
			}
			if d := strings.TrimSpace(asStr(operation["description"])); d != "" {
				descParts = append(descParts, d)
			}
			var desc *string
			if joined := strings.Join(descParts, "\n\n"); joined != "" {
				desc = &joined
			}
			method := strings.ToUpper(methodName)
			eps = append(eps, EndpointImport{
				Path:               normalizeOpenAPIPath(pathValue, prefix),
				Method:             &method,
				Description:        desc,
				QueryParams:        marshalQP(qps),
				RequestBody:        body,
				RequestContentType: contentType,
				RequestHeaders:     []byte("[]"),
			})
		}
	}

	created, skipped, err := s.store.UpsertOpenAPIEndpoints(ctx, host.ID, eps)
	if errors.Is(err, ErrNoImport) {
		return nil, apperr.Validation("В Swagger/OpenAPI документе не найдено методов для импорта")
	}
	if err != nil {
		return nil, err
	}
	result.EndpointsCreated = created
	result.EndpointsSkipped = skipped

	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "CREATE", EntityType: "openapi_import", Details: mustJSON(openAPIResultJSON(result))})
	// TODO(phase2): ws broadcast (endpoint imported)
	return result, nil
}

// ─────────────────────────── export OpenAPI ───────────────────────────

// ExportOpenAPI собирает OpenAPI 3.0 документ из эндпоинтов хоста.
func (s *Service) ExportOpenAPI(ctx context.Context, projectID, hostID int32) (map[string]any, error) {
	host, err := s.getHost(ctx, projectID, hostID)
	if err != nil {
		return nil, err
	}
	endpoints, err := s.store.ListEndpointsForHostOrdered(ctx, hostID)
	if err != nil {
		return nil, err
	}
	title := "API"
	if host.Hostname != nil && *host.Hostname != "" {
		title = *host.Hostname
	} else if host.IPAddress != nil && *host.IPAddress != "" {
		title = *host.IPAddress
	}
	document := map[string]any{
		"openapi": "3.0.0",
		"info":    map[string]any{"title": title, "version": "1.0.0"},
		"paths":   map[string]any{},
	}
	if host.Hostname != nil && *host.Hostname != "" {
		document["servers"] = []any{map[string]any{"url": "https://" + *host.Hostname}}
	} else if host.IPAddress != nil && *host.IPAddress != "" {
		document["servers"] = []any{map[string]any{"url": "http://" + *host.IPAddress}}
	}
	docPaths := document["paths"].(map[string]any)

	for i := range endpoints {
		ep := &endpoints[i]
		pathValue := ep.Path
		if pathValue == "" {
			pathValue = "/"
		}
		methodValue := "get"
		if ep.Method != nil {
			methodValue = strings.ToLower(*ep.Method)
		}
		pathItem, ok := docPaths[pathValue].(map[string]any)
		if !ok {
			pathItem = map[string]any{}
			docPaths[pathValue] = pathItem
		}
		operation := map[string]any{}
		description := ""
		if ep.Description != nil {
			description = strings.TrimSpace(*ep.Description)
		}
		if description != "" {
			first, rest, _ := strings.Cut(description, "\n\n")
			operation["summary"] = strings.TrimSpace(first)
			if strings.TrimSpace(rest) != "" {
				operation["description"] = strings.TrimSpace(rest)
			}
		}
		parameters := []any{}
		for _, raw := range decodeQPList(ep.QueryParams) {
			name := strings.TrimSpace(raw.Name)
			if name == "" {
				continue
			}
			parameter := map[string]any{
				"name":     name,
				"in":       "query",
				"required": raw.Required,
				"schema":   map[string]any{"type": "string"},
			}
			if raw.Description != nil && strings.TrimSpace(*raw.Description) != "" {
				parameter["description"] = strings.TrimSpace(*raw.Description)
			}
			if raw.Value != nil && *raw.Value != "" {
				parameter["example"] = *raw.Value
			}
			parameters = append(parameters, parameter)
		}
		for _, raw := range decodeHdrList(ep.RequestHeaders) {
			name := strings.TrimSpace(raw.Name)
			if name == "" {
				continue
			}
			parameter := map[string]any{
				"name":     name,
				"in":       "header",
				"required": false,
				"schema":   map[string]any{"type": "string"},
			}
			if raw.Value != "" {
				parameter["example"] = raw.Value
			}
			parameters = append(parameters, parameter)
		}
		if len(parameters) > 0 {
			operation["parameters"] = parameters
		}
		requestBodyText := ""
		if ep.RequestBody != nil {
			requestBodyText = strings.TrimSpace(*ep.RequestBody)
		}
		if requestBodyText != "" {
			contentType := "application/json"
			if ep.RequestContentType != nil && strings.TrimSpace(*ep.RequestContentType) != "" {
				contentType = strings.TrimSpace(*ep.RequestContentType)
			}
			var examplePayload any = requestBodyText
			if strings.Contains(strings.ToLower(contentType), "json") {
				var parsed any
				if json.Unmarshal([]byte(requestBodyText), &parsed) == nil {
					examplePayload = parsed
				}
			}
			operation["requestBody"] = map[string]any{
				"required": true,
				"content":  map[string]any{contentType: map[string]any{"example": examplePayload}},
			}
		}
		operation["responses"] = map[string]any{"200": map[string]any{"description": "OK"}}
		pathItem[methodValue] = operation
	}
	return document, nil
}

// ─────────────────────────── import JSON (PCF) ───────────────────────────

// ImportJSON импортирует активы из JSON-структуры PCF (upsert, атомарно).
func (s *Service) ImportJSON(ctx context.Context, projectID int32, payload []byte, actorID int32) (*ImportResult, error) {
	var probe any
	if err := json.Unmarshal(payload, &probe); err != nil {
		return nil, apperr.Validation("Невалидный JSON-файл")
	}
	hosts, err := parsePcfPayload(payload)
	if err != nil {
		return nil, err
	}
	result, err := s.store.ImportPCF(ctx, projectID, hosts)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "CREATE", EntityType: "import", Details: mustJSON(importResultJSON(result))})
	// TODO(phase2): ws broadcast (host imported)
	return &result, nil
}

// parsePcfPayload — распарсить+провалидировать PCF JSON и санитизировать эндпоинты.
func parsePcfPayload(payload []byte) ([]PcfHost, error) {
	var doc pcfPayloadJSON
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&doc); err != nil {
		return nil, apperr.Validation("JSON импорта не соответствует схеме PCF: " + err.Error())
	}
	hosts := make([]PcfHost, 0, len(doc.Hosts))
	for _, h := range doc.Hosts {
		if isBlank(h.IPAddress) && isBlank(h.Hostname) {
			return nil, apperr.Validation("JSON импорта не соответствует схеме PCF: каждая запись host должна содержать ip_address или hostname")
		}
		status, err := pcfStatus(h.Status)
		if err != nil {
			return nil, err
		}
		ph := PcfHost{IPAddress: h.IPAddress, Hostname: h.Hostname, Status: status, Notes: h.Notes}
		for _, p := range h.Ports {
			if p.PortNumber == nil || *p.PortNumber < 1 || *p.PortNumber > 65535 {
				return nil, apperr.Validation("JSON импорта не соответствует схеме PCF: некорректный port_number")
			}
			proto, err := pcfEnum(p.Protocol, validProtocol, ProtocolTCP)
			if err != nil {
				return nil, err
			}
			state, err := pcfEnum(p.State, validPortState, PortStateOpen)
			if err != nil {
				return nil, err
			}
			pp := PcfPort{PortNumber: int32(*p.PortNumber), Protocol: proto, State: state}
			for _, sv := range p.Services {
				if strings.TrimSpace(sv.Name) == "" {
					return nil, apperr.Validation("JSON импорта не соответствует схеме PCF: сервис должен содержать name")
				}
				pp.Services = append(pp.Services, PcfService{Name: sv.Name, Version: sv.Version, Banner: sv.Banner})
			}
			ph.Ports = append(ph.Ports, pp)
		}
		for _, e := range h.Endpoints {
			if isBlank(e.Path) && isBlank(e.RequestRaw) {
				return nil, apperr.Validation("JSON импорта не соответствует схеме PCF: каждый endpoint должен содержать path или request_raw")
			}
			ep, ok, err := sanitizeImportEndpoint(e)
			if err != nil {
				return nil, err
			}
			if !ok {
				return nil, apperr.Validation("Каждый endpoint должен содержать path или request_raw")
			}
			ph.Endpoints = append(ph.Endpoints, ep)
		}
		hosts = append(hosts, ph)
	}
	return hosts, nil
}

// sanitizeImportEndpoint прогоняет endpoint через raw+structured санитайзеры.
func sanitizeImportEndpoint(e pcfEndpointJSON) (EndpointImport, bool, error) {
	raw := EndpointRaw{
		Present:            map[string]bool{"path": true, "method": true, "description": true, "request_raw": true, "query_params": true, "request_body": true, "request_content_type": true, "request_headers": true},
		Path:               e.Path,
		Method:             upperPtr(e.Method),
		Description:        e.Description,
		RequestRaw:         e.RequestRaw,
		RequestBody:        e.RequestBody,
		RequestContentType: e.RequestContentType,
	}
	qps := make([]QueryParamInput, 0, len(e.QueryParams))
	for _, q := range e.QueryParams {
		qps = append(qps, QueryParamInput{Name: q.Name, Value: q.Value, Required: q.Required, Description: q.Description})
	}
	raw.QueryParams = &qps
	hdrs := make([]HeaderInput, 0, len(e.RequestHeaders))
	for _, h := range e.RequestHeaders {
		hdrs = append(hdrs, HeaderInput{Name: h.Name, Value: h.Value})
	}
	raw.RequestHeaders = &hdrs

	payload := buildEndpointPayload(raw)
	if err := applyRawRequestPayload(payload); err != nil {
		return EndpointImport{}, false, err
	}
	applyStructuredRequestPayload(payload)
	if !present(payload, "path") || getStr(payload, "path") == "" {
		return EndpointImport{}, false, nil
	}
	if !nonNil(payload, "request_headers") {
		payload["request_headers"] = []header{}
	}
	return EndpointImport{
		Path:               getStr(payload, "path"),
		Method:             getStrPtr(payload, "method"),
		Description:        getStrPtr(payload, "description"),
		QueryParams:        qpBytes(payload),
		RequestBody:        getStrPtr(payload, "request_body"),
		RequestContentType: getStrPtr(payload, "request_content_type"),
		RequestHeaders:     hdrBytes(payload),
	}, true, nil
}

// ─────────────────────────── payload/utf helpers ───────────────────────────

func validateOpenAPIPayload(payload []byte) error {
	if len(payload) == 0 {
		return apperr.Validation("Swagger/OpenAPI файл пуст")
	}
	if len(payload) > maxOpenAPIImportBytes {
		return apperr.Validation("Swagger/OpenAPI файл превышает 2 МБ")
	}
	return nil
}

func decodeTextPayload(payload []byte) (string, error) {
	payload = bytes.TrimPrefix(payload, []byte{0xEF, 0xBB, 0xBF}) // utf-8-sig BOM
	if !utf8.Valid(payload) {
		return "", apperr.Validation("Файл должен быть в кодировке UTF-8")
	}
	return string(payload), nil
}

// loadJSONOrYAMLDocument — порт _load_json_or_yaml_document (JSON → YAML;
// relaxed-brace-парсер Python здесь НЕ реализован — см. отчёт).
func loadJSONOrYAMLDocument(rawText string) (map[string]any, error) {
	if strings.TrimSpace(rawText) == "" {
		return nil, apperr.Validation("Swagger/OpenAPI файл пуст")
	}
	var parsed any
	if err := json.Unmarshal([]byte(rawText), &parsed); err != nil {
		if err := yaml.Unmarshal([]byte(rawText), &parsed); err != nil {
			return nil, apperr.Validation("Swagger/OpenAPI файл должен быть валидным JSON или YAML")
		}
	}
	m, ok := asMap(parsed)
	if !ok {
		return nil, apperr.Validation("Swagger/OpenAPI документ должен быть объектом")
	}
	return m, nil
}

// ─────────────────────────── OpenAPI $ref / примеры ───────────────────────────

func resolveJSONPointer(document map[string]any, ref string) (any, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, apperr.Validation("Поддерживаются только локальные $ref вида '#/...'")
	}
	var current any = document
	for _, rawToken := range strings.Split(ref[2:], "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(rawToken, "~1", "/"), "~0", "~")
		m, ok := asMap(current)
		if !ok {
			return nil, apperr.Validation("Swagger/OpenAPI содержит битую ссылку $ref: " + ref)
		}
		v, has := m[token]
		if !has {
			return nil, apperr.Validation("Swagger/OpenAPI содержит битую ссылку $ref: " + ref)
		}
		current = v
	}
	return current, nil
}

func resolveOpenAPIRef(document map[string]any, value any, depth int) (any, error) {
	if depth > 20 {
		return nil, apperr.Validation("Swagger/OpenAPI содержит слишком глубокую цепочку $ref")
	}
	m, ok := asMap(value)
	if !ok {
		return value, nil
	}
	refRaw, has := m["$ref"]
	if !has {
		return value, nil
	}
	ref, isStr := refRaw.(string)
	if !isStr {
		return nil, apperr.Validation("Некорректный $ref в Swagger/OpenAPI документе")
	}
	resolved, err := resolveJSONPointer(document, ref)
	if err != nil {
		return nil, err
	}
	if rm, ok := asMap(resolved); ok {
		merged := map[string]any{}
		for k, v := range rm {
			merged[k] = v
		}
		for k, v := range m {
			if k != "$ref" {
				merged[k] = v
			}
		}
		return resolveOpenAPIRef(document, merged, depth+1)
	}
	return resolveOpenAPIRef(document, resolved, depth+1)
}

func buildOpenAPIExampleFromSchema(document map[string]any, schema any, depth int) (any, error) {
	if schema == nil || depth > 8 {
		return nil, nil
	}
	resolvedRaw, err := resolveOpenAPIRef(document, schema, 0)
	if err != nil {
		return nil, err
	}
	resolved, ok := asMap(resolvedRaw)
	if !ok {
		return nil, nil
	}
	if v, has := resolved["example"]; has {
		return v, nil
	}
	if v, has := resolved["default"]; has {
		return v, nil
	}
	if enum, ok := asList(resolved["enum"]); ok && len(enum) > 0 {
		return enum[0], nil
	}
	schemaType := strings.ToLower(asStr(resolved["type"]))
	props, hasProps := asMap(resolved["properties"])
	if schemaType == "object" || hasProps {
		example := map[string]any{}
		for propName, propSchema := range props {
			built, err := buildOpenAPIExampleFromSchema(document, propSchema, depth+1)
			if err != nil {
				return nil, err
			}
			example[propName] = built
		}
		return example, nil
	}
	if schemaType == "array" {
		itemExample, err := buildOpenAPIExampleFromSchema(document, resolved["items"], depth+1)
		if err != nil {
			return nil, err
		}
		if itemExample != nil {
			return []any{itemExample}, nil
		}
		return []any{}, nil
	}
	switch schemaType {
	case "integer", "number":
		return 0, nil
	case "boolean":
		return false, nil
	case "file":
		return "<binary>", nil
	}
	if schemaType == "string" || schemaType == "" {
		switch strings.ToLower(asStr(resolved["format"])) {
		case "date-time":
			return "2024-01-01T00:00:00Z", nil
		case "date":
			return "2024-01-01", nil
		case "uuid":
			return "00000000-0000-0000-0000-000000000000", nil
		case "email":
			return "user@example.com", nil
		}
		return "string", nil
	}
	return nil, nil
}

func serializeOpenAPIExample(value any) *string {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case bool:
		s := "false"
		if v {
			s = "true"
		}
		return &s
	case string:
		t := strings.TrimSpace(v)
		if t == "" {
			return nil
		}
		return &t
	case map[string]any, []any:
		s := jsonDumpsIndent(v)
		return &s
	default:
		s := numToStr(value)
		return &s
	}
}

func extractOpenAPIQueryParams(document map[string]any, pathItem, operation map[string]any) ([]qparam, error) {
	collected := []qparam{}
	seen := map[string]bool{}
	for _, sourceRaw := range []any{pathItem["parameters"], operation["parameters"]} {
		source, ok := asList(sourceRaw)
		if !ok {
			continue
		}
		for _, item := range source {
			resolvedRaw, err := resolveOpenAPIRef(document, item, 0)
			if err != nil {
				return nil, err
			}
			resolved, ok := asMap(resolvedRaw)
			if !ok || strings.ToLower(asStr(resolved["in"])) != "query" {
				continue
			}
			name := strings.TrimSpace(asStr(resolved["name"]))
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			var exampleValue any
			if v, has := resolved["example"]; has {
				exampleValue = v
			} else if v, has := resolved["default"]; has {
				exampleValue = v
			} else if enum, ok := asList(resolved["enum"]); ok && len(enum) > 0 {
				exampleValue = enum[0]
			} else {
				schemaForValue := resolved["schema"]
				if _, ok := asMap(schemaForValue); !ok {
					schemaForValue = resolved
				}
				built, err := buildOpenAPIExampleFromSchema(document, schemaForValue, 0)
				if err != nil {
					return nil, err
				}
				if built != nil {
					if _, isMap := asMap(built); !isMap {
						if _, isList := asList(built); !isList {
							exampleValue = built
						}
					}
				}
			}
			var desc *string
			if d := strings.TrimSpace(asStr(resolved["description"])); d != "" {
				desc = &d
			}
			collected = append(collected, qparam{
				Name:        name,
				Value:       serializeOpenAPIExample(exampleValue),
				Required:    truthy(resolved["required"]),
				Description: desc,
			})
		}
	}
	return collected, nil
}

func extractOpenAPIRequestDetails(document map[string]any, pathItem, operation map[string]any) (*string, *string, error) {
	if requestBody, has := operation["requestBody"]; has && requestBody != nil {
		resolvedRaw, err := resolveOpenAPIRef(document, requestBody, 0)
		if err != nil {
			return nil, nil, err
		}
		if resolved, ok := asMap(resolvedRaw); ok {
			if content, ok := asMap(resolved["content"]); ok && len(content) > 0 {
				for contentType, contentSchemaRaw := range content {
					var normalizedType *string
					if t := strings.TrimSpace(contentType); t != "" {
						normalizedType = &t
					}
					contentSchema, ok := asMap(contentSchemaRaw)
					if !ok {
						return normalizedType, nil, nil
					}
					if ex, has := contentSchema["example"]; has {
						return normalizedType, serializeOpenAPIExample(ex), nil
					}
					if examples, ok := asMap(contentSchema["examples"]); ok {
						for _, exampleRaw := range examples {
							if example, ok := asMap(exampleRaw); ok {
								if val, has := example["value"]; has {
									return normalizedType, serializeOpenAPIExample(val), nil
								}
							}
						}
					}
					if schema, has := contentSchema["schema"]; has && schema != nil {
						built, err := buildOpenAPIExampleFromSchema(document, schema, 0)
						if err != nil {
							return nil, nil, err
						}
						if built != nil {
							return normalizedType, serializeOpenAPIExample(built), nil
						}
					}
					return normalizedType, nil, nil
				}
			}
		}
	}
	var consumesList []any
	if lst, ok := asList(operation["consumes"]); ok {
		consumesList = lst
	} else if lst, ok := asList(document["consumes"]); ok {
		consumesList = lst
	}
	var preferredType *string
	for _, item := range consumesList {
		if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
			t := strings.TrimSpace(s)
			preferredType = &t
			break
		}
	}
	bodyParam, formParams := collectOpenAPIFormParams(document, pathItem, operation)
	if bodyParam != nil {
		contentType := "application/json"
		if preferredType != nil {
			contentType = *preferredType
		}
		if ex, has := bodyParam["example"]; has {
			return &contentType, serializeOpenAPIExample(ex), nil
		}
		built, err := buildOpenAPIExampleFromSchema(document, bodyParam["schema"], 0)
		if err != nil {
			return nil, nil, err
		}
		if built == nil {
			return &contentType, nil, nil
		}
		return &contentType, serializeOpenAPIExample(built), nil
	}
	if len(formParams) > 0 {
		contentType := "application/x-www-form-urlencoded"
		if preferredType != nil {
			contentType = *preferredType
		}
		pairs := [][2]string{}
		for _, param := range formParams {
			name := strings.TrimSpace(asStr(param["name"]))
			if name == "" {
				continue
			}
			schemaForValue := param["schema"]
			if _, ok := asMap(schemaForValue); !ok {
				schemaForValue = param
			}
			built, err := buildOpenAPIExampleFromSchema(document, schemaForValue, 0)
			if err != nil {
				return nil, nil, err
			}
			valueText := ""
			if s := serializeOpenAPIExample(built); s != nil {
				valueText = *s
			}
			pairs = append(pairs, [2]string{name, valueText})
		}
		if len(pairs) == 0 {
			return &contentType, nil, nil
		}
		items := make([]string, 0, len(pairs))
		for _, p := range pairs {
			items = append(items, p[0]+"="+p[1])
		}
		sep := "&"
		if strings.HasPrefix(contentType, "multipart") {
			sep = "\n"
		}
		bodyText := strings.Join(items, sep)
		if bodyText == "" {
			return &contentType, nil, nil
		}
		return &contentType, &bodyText, nil
	}
	return nil, nil, nil
}

func collectOpenAPIFormParams(document map[string]any, pathItem, operation map[string]any) (map[string]any, []map[string]any) {
	var bodyParam map[string]any
	formParams := []map[string]any{}
	for _, sourceRaw := range []any{pathItem["parameters"], operation["parameters"]} {
		source, ok := asList(sourceRaw)
		if !ok {
			continue
		}
		for _, item := range source {
			resolvedRaw, err := resolveOpenAPIRef(document, item, 0)
			if err != nil {
				continue
			}
			resolved, ok := asMap(resolvedRaw)
			if !ok {
				continue
			}
			inValue := strings.ToLower(asStr(resolved["in"]))
			if inValue == "body" && bodyParam == nil {
				bodyParam = resolved
			} else if inValue == "formdata" {
				formParams = append(formParams, resolved)
			}
		}
	}
	return bodyParam, formParams
}

func normalizeOpenAPIPath(pathValue, prefix string) string {
	combined := pathValue
	if prefix != "" {
		combined = strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(pathValue, "/")
	}
	normalized := normalizeEndpointPath(combined)
	if normalized == "" {
		return "/"
	}
	return normalized
}

func extractOpenAPIHost(document map[string]any) *string {
	swaggerHost := strings.TrimSpace(asStr(document["host"]))
	if swaggerHost != "" {
		stripped := reHTTPScheme.ReplaceAllString(swaggerHost, "")
		host := strings.SplitN(stripped, "/", 2)[0]
		return &host
	}
	servers, ok := asList(document["servers"])
	if !ok {
		return nil
	}
	for _, serverRaw := range servers {
		server, ok := asMap(serverRaw)
		if !ok {
			continue
		}
		rawURL := strings.TrimSpace(asStr(server["url"]))
		if rawURL == "" || !strings.Contains(rawURL, "://") {
			continue
		}
		if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
			h := u.Host
			return &h
		}
	}
	return nil
}

func extractPathPrefix(document map[string]any) string {
	basePath := strings.TrimSpace(asStr(document["basePath"]))
	if basePath != "" {
		return basePath
	}
	servers, ok := asList(document["servers"])
	if !ok {
		return ""
	}
	for _, serverRaw := range servers {
		server, ok := asMap(serverRaw)
		if !ok {
			continue
		}
		rawURL := strings.TrimSpace(asStr(server["url"]))
		if rawURL == "" {
			continue
		}
		parseTarget := rawURL
		if !strings.Contains(rawURL, "://") {
			parseTarget = "https://placeholder.local" + rawURL
		}
		if u, err := url.Parse(parseTarget); err == nil && u.Path != "" && u.Path != "/" {
			return u.Path
		}
	}
	return ""
}

// ─────────────────────────── generic value helpers ───────────────────────────

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func asList(v any) ([]any, bool) {
	l, ok := v.([]any)
	return l, ok
}

func asStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	case int:
		return x != 0
	case int64:
		return x != 0
	default:
		return true
	}
}

func numToStr(v any) string {
	switch n := v.(type) {
	case float64:
		if n == math.Trunc(n) && math.Abs(n) < 1e15 {
			return strconv.FormatInt(int64(n), 10)
		}
		return strconv.FormatFloat(n, 'g', -1, 64)
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func jsonDumpsIndent(v any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return strings.TrimRight(buf.String(), "\n")
}

func marshalQP(qps []qparam) []byte {
	if len(qps) == 0 {
		return []byte("[]")
	}
	b, _ := json.Marshal(qps)
	return b
}

// decodeQPList/decodeHdrList — распаковать JSON-колонку в типизированные списки.
func decodeQPList(raw []byte) []qparam {
	if len(raw) == 0 {
		return nil
	}
	var out []qparam
	_ = json.Unmarshal(raw, &out)
	return out
}

func decodeHdrList(raw []byte) []header {
	if len(raw) == 0 {
		return nil
	}
	var out []header
	_ = json.Unmarshal(raw, &out)
	return out
}

func isBlank(s *string) bool { return s == nil || strings.TrimSpace(*s) == "" }

func upperPtr(s *string) *string {
	if s == nil {
		return nil
	}
	u := strings.ToUpper(*s)
	return &u
}

func pcfStatus(v *string) (string, error) {
	if v == nil || *v == "" {
		return HostStatusUnknown, nil
	}
	up := strings.ToUpper(*v)
	if !validHostStatus[up] {
		return "", apperr.Validation("JSON импорта не соответствует схеме PCF: недопустимый status")
	}
	return up, nil
}

func pcfEnum(v *string, allowed map[string]bool, def string) (string, error) {
	if v == nil || *v == "" {
		return def, nil
	}
	up := strings.ToUpper(*v)
	if !allowed[up] {
		return "", apperr.Validation("JSON импорта не соответствует схеме PCF: недопустимое значение enum")
	}
	return up, nil
}

// ─────────────────────────── PCF JSON parse structs ───────────────────────────

type pcfPayloadJSON struct {
	Hosts []pcfHostJSON `json:"hosts"`
}

type pcfHostJSON struct {
	IPAddress *string           `json:"ip_address"`
	Hostname  *string           `json:"hostname"`
	Status    *string           `json:"status"`
	Notes     *string           `json:"notes"`
	Ports     []pcfPortJSON     `json:"ports"`
	Endpoints []pcfEndpointJSON `json:"endpoints"`
}

type pcfPortJSON struct {
	PortNumber *int             `json:"port_number"`
	Protocol   *string          `json:"protocol"`
	State      *string          `json:"state"`
	Services   []pcfServiceJSON `json:"services"`
}

type pcfServiceJSON struct {
	Name    string  `json:"name"`
	Version *string `json:"version"`
	Banner  *string `json:"banner"`
}

type pcfEndpointJSON struct {
	Path               *string   `json:"path"`
	Method             *string   `json:"method"`
	Description        *string   `json:"description"`
	RequestRaw         *string   `json:"request_raw"`
	QueryParams        []qpJSON  `json:"query_params"`
	RequestBody        *string   `json:"request_body"`
	RequestContentType *string   `json:"request_content_type"`
	RequestHeaders     []hdrJSON `json:"request_headers"`
}

type qpJSON struct {
	Name        string  `json:"name"`
	Value       *string `json:"value"`
	Required    bool    `json:"required"`
	Description *string `json:"description"`
}

type hdrJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// openAPIResultJSON/importResultJSON — details аудита в snake_case как в Python.
func openAPIResultJSON(r *OpenAPIImportResult) map[string]any {
	return map[string]any{
		"host_id":           r.HostID,
		"spec_host":         r.SpecHost,
		"endpoints_created": r.EndpointsCreated,
		"endpoints_skipped": r.EndpointsSkipped,
		"errors":            r.Errors,
	}
}

func importResultJSON(r ImportResult) map[string]any {
	return map[string]any{
		"hosts_created":     r.HostsCreated,
		"ports_created":     r.PortsCreated,
		"services_created":  r.ServicesCreated,
		"endpoints_created": r.EndpointsCreated,
		"errors":            r.Errors,
	}
}
