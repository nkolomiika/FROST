package http

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/inventory"
)

// ─────────────────────────── enum helpers (API lower ↔ домен UPPER) ───────────────────────────

func hostStatusLower(s *apiv1.HostStatus) *string {
	if s == nil {
		return nil
	}
	v := string(*s)
	return &v
}

func osTypeLower(s *apiv1.OsType) *string {
	if s == nil {
		return nil
	}
	v := string(*s)
	return &v
}

func protocolLower(s *apiv1.Protocol) *string {
	if s == nil {
		return nil
	}
	v := string(*s)
	return &v
}

func portStateLower(s *apiv1.PortState) *string {
	if s == nil {
		return nil
	}
	v := string(*s)
	return &v
}

func methodStr(m *apiv1.HttpMethod) *string {
	if m == nil {
		return nil
	}
	v := string(*m)
	return &v
}

func methodOut(m *string) *apiv1.HttpMethod {
	if m == nil {
		return nil
	}
	v := apiv1.HttpMethod(*m)
	return &v
}

func itoa32(v int32) string { return strconv.Itoa(int(v)) }

// ─────────────────────────── typed DTO мапперы ───────────────────────────

func serviceOut(s *inventory.PortService) apiv1.ServiceOut {
	return apiv1.ServiceOut{
		Id:        int(s.ID),
		PortId:    int(s.PortID),
		Name:      s.Name,
		Version:   s.Version,
		Banner:    s.Banner,
		CreatedAt: s.CreatedAt,
		UpdatedAt: s.UpdatedAt,
	}
}

func portOut(agg *inventory.PortAggregate) apiv1.PortOut {
	services := make([]apiv1.ServiceOut, 0, len(agg.Services))
	for i := range agg.Services {
		services = append(services, serviceOut(&agg.Services[i]))
	}
	return apiv1.PortOut{
		Id:          int(agg.Port.ID),
		HostId:      int(agg.Port.HostID),
		IpAddressId: int(agg.Port.IPAddressID),
		PortNumber:  int(agg.Port.PortNumber),
		Protocol:    apiv1.Protocol(strings.ToLower(agg.Port.Protocol)),
		State:       apiv1.PortState(strings.ToLower(agg.Port.State)),
		HttpStatus:  int32Ptr(agg.Port.HTTPStatus),
		Services:    &services,
		CreatedAt:   agg.Port.CreatedAt,
		UpdatedAt:   agg.Port.UpdatedAt,
	}
}

func ipAddressOut(agg *inventory.IPAggregate) apiv1.HostIpAddressOut {
	ports := make([]apiv1.PortOut, 0, len(agg.Ports))
	for i := range agg.Ports {
		ports = append(ports, portOut(&agg.Ports[i]))
	}
	return apiv1.HostIpAddressOut{
		Id:           int(agg.IP.ID),
		HostId:       int(agg.IP.HostID),
		IpAddress:    agg.IP.IPAddress,
		Label:        agg.IP.Label,
		IsPrimary:    agg.IP.IsPrimary,
		Hostnames:    parseHostnames(agg.IP.Hostnames),
		IsCloudflare: agg.IP.IsCloudflare,
		Ports:        &ports,
		CreatedAt:    agg.IP.CreatedAt,
		UpdatedAt:    agg.IP.UpdatedAt,
	}
}

func hostOut(agg *inventory.HostAggregate) apiv1.HostOut {
	ips := make([]apiv1.HostIpAddressOut, 0, len(agg.IPs))
	for i := range agg.IPs {
		ips = append(ips, ipAddressOut(&agg.IPs[i]))
	}
	return apiv1.HostOut{
		Id:          int(agg.Host.ID),
		ProjectId:   int(agg.Host.ProjectID),
		IpAddress:   agg.Host.IPAddress,
		IpAddresses: &ips,
		Hostname:    agg.Host.Hostname,
		Status:      apiv1.HostStatus(strings.ToLower(agg.Host.Status)),
		OsType:      ptr(apiv1.OsType(strings.ToLower(agg.Host.OsType))),
		Notes:       agg.Host.Notes,
		Origin:      ptr(agg.Host.Origin),
		CreatedAt:   agg.Host.CreatedAt,
		UpdatedAt:   agg.Host.UpdatedAt,
	}
}

func endpointOut(e *inventory.Endpoint) apiv1.EndpointOut {
	return apiv1.EndpointOut{
		Id:                 int(e.ID),
		HostId:             int(e.HostID),
		Path:               e.Path,
		Method:             methodOut(e.Method),
		Description:        e.Description,
		QueryParams:        parseQueryParams(e.QueryParams),
		RequestBody:        e.RequestBody,
		RequestContentType: e.RequestContentType,
		RequestHeaders:     parseHeaders(e.RequestHeaders),
		CreatedAt:          e.CreatedAt,
		UpdatedAt:          e.UpdatedAt,
	}
}

func openAPIImportResultOut(r *inventory.OpenAPIImportResult) apiv1.OpenApiImportResult {
	errs := r.Errors
	return apiv1.OpenApiImportResult{
		HostId:           int(r.HostID),
		SpecHost:         r.SpecHost,
		EndpointsCreated: r.EndpointsCreated,
		EndpointsSkipped: r.EndpointsSkipped,
		Errors:           &errs,
	}
}

func importResultOut(r *inventory.ImportResult) apiv1.ImportResult {
	return apiv1.ImportResult{
		HostsCreated:     r.HostsCreated,
		PortsCreated:     r.PortsCreated,
		ServicesCreated:  r.ServicesCreated,
		EndpointsCreated: r.EndpointsCreated,
		Errors:           r.Errors,
	}
}

// ─────────────────────────── bespoke JSON (list_hosts / get_host) ───────────────────────────

func serviceMap(s *inventory.PortService) map[string]any {
	return map[string]any{
		"id":         s.ID,
		"port_id":    s.PortID,
		"name":       s.Name,
		"version":    s.Version,
		"banner":     s.Banner,
		"created_at": s.CreatedAt,
		"updated_at": s.UpdatedAt,
	}
}

func portMap(agg *inventory.PortAggregate) map[string]any {
	services := make([]map[string]any, 0, len(agg.Services))
	for i := range agg.Services {
		services = append(services, serviceMap(&agg.Services[i]))
	}
	return map[string]any{
		"id":            agg.Port.ID,
		"host_id":       agg.Port.HostID,
		"ip_address_id": agg.Port.IPAddressID,
		"port_number":   agg.Port.PortNumber,
		"protocol":      strings.ToLower(agg.Port.Protocol),
		"state":         strings.ToLower(agg.Port.State),
		"http_status":   agg.Port.HTTPStatus,
		"services":      services,
		"created_at":    agg.Port.CreatedAt,
		"updated_at":    agg.Port.UpdatedAt,
	}
}

func ipAddressMap(agg *inventory.IPAggregate) map[string]any {
	ports := make([]map[string]any, 0, len(agg.Ports))
	for i := range agg.Ports {
		ports = append(ports, portMap(&agg.Ports[i]))
	}
	return map[string]any{
		"id":            agg.IP.ID,
		"host_id":       agg.IP.HostID,
		"ip_address":    agg.IP.IPAddress,
		"label":         agg.IP.Label,
		"is_primary":    agg.IP.IsPrimary,
		"hostnames":     rawJSONOrEmptyArray(agg.IP.Hostnames),
		"is_cloudflare": agg.IP.IsCloudflare,
		"ports":         ports,
		"created_at":    agg.IP.CreatedAt,
		"updated_at":    agg.IP.UpdatedAt,
	}
}

func hostIPList(agg *inventory.HostAggregate) []map[string]any {
	ips := make([]map[string]any, 0, len(agg.IPs))
	for i := range agg.IPs {
		ips = append(ips, ipAddressMap(&agg.IPs[i]))
	}
	return ips
}

// hostListItem — элемент list_hosts (endpoints — краткая сводка {id,path,method}).
func hostListItem(agg *inventory.HostAggregate) map[string]any {
	endpoints := make([]map[string]any, 0, len(agg.Endpoints))
	for i := range agg.Endpoints {
		e := &agg.Endpoints[i]
		endpoints = append(endpoints, map[string]any{
			"id":     e.ID,
			"path":   e.Path,
			"method": e.Method,
		})
	}
	return map[string]any{
		"id":           agg.Host.ID,
		"project_id":   agg.Host.ProjectID,
		"ip_address":   agg.Host.IPAddress,
		"ip_addresses": hostIPList(agg),
		"endpoints":    endpoints,
		"hostname":     agg.Host.Hostname,
		"status":       strings.ToLower(agg.Host.Status),
		"os_type":      strings.ToLower(agg.Host.OsType),
		"notes":        agg.Host.Notes,
		"origin":       agg.Host.Origin,
		"created_at":   agg.Host.CreatedAt,
		"updated_at":   agg.Host.UpdatedAt,
	}
}

// hostDetail — get_host (полные endpoints и вложенные ip_addresses→ports→services).
func hostDetail(agg *inventory.HostAggregate) map[string]any {
	endpoints := make([]map[string]any, 0, len(agg.Endpoints))
	for i := range agg.Endpoints {
		e := &agg.Endpoints[i]
		endpoints = append(endpoints, map[string]any{
			"id":                   e.ID,
			"host_id":              e.HostID,
			"path":                 e.Path,
			"method":               e.Method,
			"description":          e.Description,
			"query_params":         rawJSONOrEmptyArray(e.QueryParams),
			"request_body":         e.RequestBody,
			"request_content_type": e.RequestContentType,
			"request_headers":      rawJSONOrEmptyArray(e.RequestHeaders),
			"created_at":           e.CreatedAt,
			"updated_at":           e.UpdatedAt,
		})
	}
	return map[string]any{
		"id":           agg.Host.ID,
		"project_id":   agg.Host.ProjectID,
		"ip_address":   agg.Host.IPAddress,
		"ip_addresses": hostIPList(agg),
		"hostname":     agg.Host.Hostname,
		"status":       strings.ToLower(agg.Host.Status),
		"os_type":      strings.ToLower(agg.Host.OsType),
		"notes":        agg.Host.Notes,
		"origin":       agg.Host.Origin,
		"created_at":   agg.Host.CreatedAt,
		"updated_at":   agg.Host.UpdatedAt,
		"endpoints":    endpoints,
	}
}

// ─────────────────────────── JSON-колонки ───────────────────────────

// rawJSONOrEmptyArray: JSON-колонка → any для вложения (пустая/NULL → []).
func rawJSONOrEmptyArray(raw json.RawMessage) any {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return []any{}
	}
	return raw
}

func parseHostnames(raw json.RawMessage) *[]apiv1.HostnameResolutionOut {
	out := []apiv1.HostnameResolutionOut{}
	if s := strings.TrimSpace(string(raw)); s != "" && s != "null" {
		_ = json.Unmarshal(raw, &out)
	}
	return &out
}

func parseQueryParams(raw json.RawMessage) *[]apiv1.EndpointQueryParam {
	out := []apiv1.EndpointQueryParam{}
	if s := strings.TrimSpace(string(raw)); s != "" && s != "null" {
		_ = json.Unmarshal(raw, &out)
	}
	return &out
}

func parseHeaders(raw json.RawMessage) *[]apiv1.EndpointRequestHeader {
	out := []apiv1.EndpointRequestHeader{}
	if s := strings.TrimSpace(string(raw)); s != "" && s != "null" {
		_ = json.Unmarshal(raw, &out)
	}
	return &out
}

// ─────────────────────────── endpoint raw payload builders ───────────────────────────

func endpointCreateRaw(req apiv1.EndpointCreate) inventory.EndpointRaw {
	qp := convQueryParams(req.QueryParams)
	if qp == nil {
		qp = &[]inventory.QueryParamInput{}
	}
	hd := convHeaders(req.RequestHeaders)
	if hd == nil {
		hd = &[]inventory.HeaderInput{}
	}
	return inventory.EndpointRaw{
		Present: map[string]bool{
			"path": true, "method": true, "description": true, "request_raw": true,
			"query_params": true, "request_body": true, "request_content_type": true, "request_headers": true,
		},
		Path:               req.Path,
		Method:             methodStr(req.Method),
		Description:        req.Description,
		RequestRaw:         req.RequestRaw,
		QueryParams:        qp,
		RequestBody:        req.RequestBody,
		RequestContentType: req.RequestContentType,
		RequestHeaders:     hd,
	}
}

func endpointUpdateRaw(req apiv1.EndpointUpdate, keys bodyKey) inventory.EndpointRaw {
	present := map[string]bool{}
	for _, k := range []string{"path", "method", "description", "request_raw", "query_params", "request_body", "request_content_type", "request_headers"} {
		present[k] = keys.has(k)
	}
	return inventory.EndpointRaw{
		Present:            present,
		Path:               req.Path,
		Method:             methodStr(req.Method),
		Description:        req.Description,
		RequestRaw:         req.RequestRaw,
		QueryParams:        convQueryParams(req.QueryParams),
		RequestBody:        req.RequestBody,
		RequestContentType: req.RequestContentType,
		RequestHeaders:     convHeaders(req.RequestHeaders),
	}
}

func convQueryParams(in *[]apiv1.EndpointQueryParam) *[]inventory.QueryParamInput {
	if in == nil {
		return nil
	}
	out := make([]inventory.QueryParamInput, 0, len(*in))
	for _, q := range *in {
		item := inventory.QueryParamInput{Name: q.Name, Value: q.Value, Description: q.Description}
		if q.Required != nil {
			item.Required = *q.Required
		}
		out = append(out, item)
	}
	return &out
}

func convHeaders(in *[]apiv1.EndpointRequestHeader) *[]inventory.HeaderInput {
	if in == nil {
		return nil
	}
	out := make([]inventory.HeaderInput, 0, len(*in))
	for _, hh := range *in {
		value := ""
		if hh.Value != nil {
			value = *hh.Value
		}
		out = append(out, inventory.HeaderInput{Name: hh.Name, Value: value})
	}
	return &out
}
