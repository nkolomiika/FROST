package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nkolomiika/frost/internal/apperr"
)

// Service — use-cases контекста inventory. Зависит только от портов.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService собирает сервис. now можно подменить в тестах.
func NewService(store Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}
}

func (s *Service) audit(ctx context.Context, e AuditEntry) { _ = s.store.InsertAudit(ctx, e) }

// ─────────────────────────── входные структуры (граница http) ───────────────────────────

type HostCreateInput struct {
	IPAddress   *string
	IPAddresses []string
	Hostname    *string
	Status      *string // lowercase (API)
	OsType      *string // lowercase (API)
	Notes       *string
}

type HostUpdateInput struct {
	IPAddressPresent   bool
	IPAddress          *string
	IPAddressesPresent bool
	IPAddresses        []RawIPEntry
	Hostname           *string
	Status             *string
	OsType             *string
	Notes              *string
}

type PortCreateInput struct {
	IPAddressID int32
	PortNumber  int32
	Protocol    *string
	State       *string
	HTTPStatus  *int32
}

type PortUpdateInput struct {
	IPAddressID *int32
	PortNumber  *int32
	Protocol    *string
	State       *string
	HTTPStatus  *int32
}

// EndpointRaw — сырой payload эндпоинта с признаками присутствия ключей (для
// точного повторения model_dump(exclude_unset)). Для create все Present=true.
type EndpointRaw struct {
	Present            map[string]bool
	Path               *string
	Method             *string // UPPER
	Description        *string
	RequestRaw         *string
	QueryParams        *[]QueryParamInput
	RequestBody        *string
	RequestContentType *string
	RequestHeaders     *[]HeaderInput
}

// QueryParamInput/HeaderInput — нейтральные типы с границы http.
type QueryParamInput struct {
	Name        string
	Value       *string
	Required    bool
	Description *string
}

type HeaderInput struct {
	Name  string
	Value string
}

// ─────────────────────────── hosts ───────────────────────────

func (s *Service) getHost(ctx context.Context, projectID, hostID int32) (*Host, error) {
	h, err := s.store.GetHost(ctx, projectID, hostID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Хост не найден")
	}
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (s *Service) loadOne(ctx context.Context, projectID, hostID int32) (*HostAggregate, error) {
	h, err := s.getHost(ctx, projectID, hostID)
	if err != nil {
		return nil, err
	}
	aggs, err := s.store.LoadTrees(ctx, []Host{*h})
	if err != nil {
		return nil, err
	}
	return &aggs[0], nil
}

// ListHosts — список хостов проекта (origin host|ip|all; status-фильтр).
func (s *Service) ListHosts(ctx context.Context, projectID int32, page, size int, statusFilter, origin string) ([]HostAggregate, int64, error) {
	status := ""
	if statusFilter != "" {
		status = strings.ToUpper(statusFilter)
		if !validHostStatus[status] {
			return []HostAggregate{}, 0, nil
		}
	}
	originFilter := origin
	if origin == "all" {
		originFilter = ""
	}
	hosts, total, err := s.store.ListHostsPage(ctx, HostListParams{
		ProjectID: projectID, Origin: originFilter, Status: status,
		Offset: int32((page - 1) * size), Limit: int32(size),
	})
	if err != nil {
		return nil, 0, err
	}
	aggs, err := s.store.LoadTrees(ctx, hosts)
	if err != nil {
		return nil, 0, err
	}
	return aggs, total, nil
}

// GetHost — хост с вложенными сущностями.
func (s *Service) GetHost(ctx context.Context, projectID, hostID int32) (*HostAggregate, error) {
	return s.loadOne(ctx, projectID, hostID)
}

// CreateHost создаёт хост (origin всегда 'host').
func (s *Service) CreateHost(ctx context.Context, projectID int32, in HostCreateInput, actorID int32) (*HostAggregate, error) {
	merged := []string{}
	seen := map[string]bool{}
	consider := []string{}
	if in.IPAddress != nil {
		consider = append(consider, *in.IPAddress)
	}
	consider = append(consider, in.IPAddresses...)
	for _, raw := range consider {
		if raw == "" {
			continue
		}
		v := strings.TrimSpace(raw)
		if v != "" && !seen[v] {
			seen[v] = true
			merged = append(merged, v)
		}
	}
	if len(merged) == 0 && (in.Hostname == nil || *in.Hostname == "") {
		return nil, apperr.Validation("Нужно указать хотя бы один ip_address или hostname")
	}

	var primaryIP *string
	if len(merged) > 0 {
		p := merged[0]
		primaryIP = &p
	}
	rawEntries := make([]RawIPEntry, 0, len(merged))
	for _, m := range merged {
		mm := m
		rawEntries = append(rawEntries, RawIPEntry{IPAddress: &mm})
	}
	entries := normalizeHostIPEntries(primaryIP, rawEntries)

	status, err := normalizeStatus(in.Status)
	if err != nil {
		return nil, err
	}
	osType, err := normalizeOsType(in.OsType)
	if err != nil {
		return nil, err
	}

	nh := NewHost{
		ProjectID: projectID,
		IPAddress: primaryMirror(entries),
		Hostname:  in.Hostname,
		Status:    status,
		OsType:    osType,
		Notes:     in.Notes,
		Origin:    "host",
	}
	hostID, err := s.store.CreateHost(ctx, nh, entries)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "CREATE", EntityType: "host", EntityID: &hostID})
	// TODO(phase2): ws broadcast (host created)
	return s.loadOne(ctx, projectID, hostID)
}

// UpdateHost обновляет хост (partial), с нормализацией IP-записей при их присылке.
func (s *Service) UpdateHost(ctx context.Context, projectID, hostID int32, in HostUpdateInput, actorID int32) (*HostAggregate, error) {
	host, err := s.getHost(ctx, projectID, hostID)
	if err != nil {
		return nil, err
	}
	fields := HostFields{
		IPAddress: host.IPAddress,
		Hostname:  host.Hostname,
		Status:    host.Status,
		OsType:    host.OsType,
		Notes:     host.Notes,
	}
	if in.Hostname != nil {
		fields.Hostname = in.Hostname
	}
	if in.Status != nil {
		st, err := normalizeStatus(in.Status)
		if err != nil {
			return nil, err
		}
		fields.Status = st
	}
	if in.OsType != nil {
		ot, err := normalizeOsType(in.OsType)
		if err != nil {
			return nil, err
		}
		fields.OsType = ot
	}
	if in.Notes != nil {
		fields.Notes = in.Notes
	}

	hasIPPayload := in.IPAddressPresent || in.IPAddressesPresent
	params := HostUpdateParams{HostID: hostID, Fields: fields}
	if hasIPPayload {
		entries := normalizeHostIPEntries(in.IPAddress, in.IPAddresses)
		if len(entries) == 0 && (fields.Hostname == nil || *fields.Hostname == "") {
			return nil, apperr.Validation("Нужно указать хотя бы один IP-адрес или hostname")
		}
		params.Fields.IPAddress = primaryMirror(entries)
		params.ReplaceIPs = true
		params.Entries = entries
	}
	if err := s.store.UpdateHost(ctx, params); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "host", EntityID: &hostID})
	// TODO(phase2): ws broadcast (host updated)
	return s.loadOne(ctx, projectID, hostID)
}

// DeleteHost удаляет хост.
func (s *Service) DeleteHost(ctx context.Context, projectID, hostID, actorID int32) error {
	host, err := s.getHost(ctx, projectID, hostID)
	if err != nil {
		return err
	}
	details := mustJSON(map[string]any{
		"project_id": itoa(projectID),
		"hostname":   host.Hostname,
		"ip_address": host.IPAddress,
	})
	if err := s.store.DeleteHost(ctx, projectID, hostID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "DELETE", EntityType: "host", EntityID: &hostID, Details: details})
	// TODO(phase2): ws broadcast (host deleted)
	return nil
}

// ─────────────────────────── ports ───────────────────────────

// ListPorts — порты хоста (без проверки принадлежности хоста проекту, как в Python).
func (s *Service) ListPorts(ctx context.Context, hostID int32) ([]PortAggregate, error) {
	ports, err := s.store.ListPortsForHost(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return s.loadPortServices(ctx, ports)
}

func (s *Service) loadPortServices(ctx context.Context, ports []Port) ([]PortAggregate, error) {
	out := make([]PortAggregate, 0, len(ports))
	for i := range ports {
		svcs, err := s.store.ListServicesForPort(ctx, ports[i].ID)
		if err != nil {
			return nil, err
		}
		out = append(out, PortAggregate{Port: ports[i], Services: svcs})
	}
	return out, nil
}

func (s *Service) getPort(ctx context.Context, hostID, portID int32) (*Port, error) {
	p, err := s.store.GetPort(ctx, hostID, portID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Порт не найден")
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Service) ensureHostIP(ctx context.Context, hostID, ipID int32) error {
	_, err := s.store.GetHostIP(ctx, hostID, ipID)
	if errors.Is(err, ErrNoRows) {
		return apperr.Validation("IP-адрес не принадлежит указанному хосту")
	}
	return err
}

// GetPort — порт по id.
func (s *Service) GetPort(ctx context.Context, hostID, portID int32) (*PortAggregate, error) {
	p, err := s.getPort(ctx, hostID, portID)
	if err != nil {
		return nil, err
	}
	svcs, err := s.store.ListServicesForPort(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	return &PortAggregate{Port: *p, Services: svcs}, nil
}

// CreatePort создаёт порт хоста.
func (s *Service) CreatePort(ctx context.Context, projectID, hostID int32, in PortCreateInput, actorID int32) (*PortAggregate, error) {
	if _, err := s.getHost(ctx, projectID, hostID); err != nil {
		return nil, err
	}
	if err := s.ensureHostIP(ctx, hostID, in.IPAddressID); err != nil {
		return nil, err
	}
	if err := validatePortNumber(in.PortNumber); err != nil {
		return nil, err
	}
	protocol, err := normalizeProtocol(in.Protocol)
	if err != nil {
		return nil, err
	}
	state, err := normalizePortState(in.State)
	if err != nil {
		return nil, err
	}
	dup, err := s.store.FindPortDup(ctx, in.IPAddressID, in.PortNumber, protocol, 0)
	if err != nil {
		return nil, err
	}
	if dup {
		return nil, apperr.Conflict("Порт с таким номером и протоколом уже существует на этом IP")
	}
	port, err := s.store.InsertPort(ctx, NewPort{
		HostID: hostID, IPAddressID: in.IPAddressID, PortNumber: in.PortNumber,
		Protocol: protocol, State: state, HTTPStatus: in.HTTPStatus,
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "CREATE", EntityType: "port", EntityID: &port.ID})
	// TODO(phase2): ws broadcast (port created)
	return &PortAggregate{Port: *port, Services: []PortService{}}, nil
}

// UpdatePort обновляет порт.
func (s *Service) UpdatePort(ctx context.Context, projectID, hostID, portID int32, in PortUpdateInput, actorID int32) (*PortAggregate, error) {
	port, err := s.getPort(ctx, hostID, portID)
	if err != nil {
		return nil, err
	}
	nextPortNumber := port.PortNumber
	if in.PortNumber != nil {
		if err := validatePortNumber(*in.PortNumber); err != nil {
			return nil, err
		}
		nextPortNumber = *in.PortNumber
	}
	nextProtocol := port.Protocol
	if in.Protocol != nil {
		nextProtocol, err = normalizeProtocol(in.Protocol)
		if err != nil {
			return nil, err
		}
	}
	nextIPID := port.IPAddressID
	if in.IPAddressID != nil {
		nextIPID = *in.IPAddressID
	}
	if nextIPID != port.IPAddressID {
		if err := s.ensureHostIP(ctx, hostID, nextIPID); err != nil {
			return nil, err
		}
	}
	dup, err := s.store.FindPortDup(ctx, nextIPID, nextPortNumber, nextProtocol, port.ID)
	if err != nil {
		return nil, err
	}
	if dup {
		return nil, apperr.Conflict("Порт с таким номером и протоколом уже существует на этом IP")
	}
	nextState := port.State
	if in.State != nil {
		nextState, err = normalizePortState(in.State)
		if err != nil {
			return nil, err
		}
	}
	nextHTTP := port.HTTPStatus
	if in.HTTPStatus != nil {
		nextHTTP = in.HTTPStatus
	}
	updated, err := s.store.UpdatePort(ctx, UpdatePortParams{
		ID: port.ID, IPAddressID: nextIPID, PortNumber: nextPortNumber,
		Protocol: nextProtocol, State: nextState, HTTPStatus: nextHTTP,
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "port", EntityID: &updated.ID})
	// TODO(phase2): ws broadcast (port updated)
	svcs, err := s.store.ListServicesForPort(ctx, updated.ID)
	if err != nil {
		return nil, err
	}
	return &PortAggregate{Port: *updated, Services: svcs}, nil
}

// DeletePort удаляет порт.
func (s *Service) DeletePort(ctx context.Context, projectID, hostID, portID, actorID int32) error {
	port, err := s.getPort(ctx, hostID, portID)
	if err != nil {
		return err
	}
	if err := s.store.DeletePort(ctx, port.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "DELETE", EntityType: "port", EntityID: &port.ID})
	// TODO(phase2): ws broadcast (port deleted)
	return nil
}

// ─────────────────────────── services ───────────────────────────

// ListServices — сервисы порта (без проверки принадлежности, как в Python).
func (s *Service) ListServices(ctx context.Context, portID int32) ([]PortService, error) {
	return s.store.ListServicesForPort(ctx, portID)
}

// CreateService создаёт сервис.
func (s *Service) CreateService(ctx context.Context, projectID, hostID, portID int32, name string, version, banner *string, actorID int32) (*PortService, error) {
	if _, err := s.getHost(ctx, projectID, hostID); err != nil {
		return nil, err
	}
	if _, err := s.getPort(ctx, hostID, portID); err != nil {
		return nil, err
	}
	svc, err := s.store.InsertService(ctx, portID, name, version, banner)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "CREATE", EntityType: "service", EntityID: &svc.ID})
	// TODO(phase2): ws broadcast (service created)
	return svc, nil
}

// UpdateService обновляет сервис.
func (s *Service) UpdateService(ctx context.Context, projectID, hostID, portID, serviceID int32, name, version, banner *string, actorID int32) (*PortService, error) {
	if _, err := s.getHost(ctx, projectID, hostID); err != nil {
		return nil, err
	}
	if _, err := s.getPort(ctx, hostID, portID); err != nil {
		return nil, err
	}
	svc, err := s.store.GetServiceForPort(ctx, portID, serviceID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Сервис не найден")
	}
	if err != nil {
		return nil, err
	}
	name2 := svc.Name
	if name != nil {
		name2 = *name
	}
	version2 := svc.Version
	if version != nil {
		version2 = version
	}
	banner2 := svc.Banner
	if banner != nil {
		banner2 = banner
	}
	updated, err := s.store.UpdateService(ctx, svc.ID, name2, version2, banner2)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "service", EntityID: &updated.ID})
	// TODO(phase2): ws broadcast (service updated)
	return updated, nil
}

// DeleteService удаляет сервис (проверяется только принадлежность порту).
func (s *Service) DeleteService(ctx context.Context, projectID, portID, serviceID, actorID int32) error {
	svc, err := s.store.GetServiceForPort(ctx, portID, serviceID)
	if errors.Is(err, ErrNoRows) {
		return apperr.NotFound("Сервис не найден")
	}
	if err != nil {
		return err
	}
	if err := s.store.DeleteService(ctx, svc.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "DELETE", EntityType: "service", EntityID: &svc.ID})
	// TODO(phase2): ws broadcast (service deleted)
	return nil
}

// ─────────────────────────── endpoints ───────────────────────────

// ListEndpoints — эндпоинты хоста (order created_at desc; без проверки хоста).
func (s *Service) ListEndpoints(ctx context.Context, hostID int32) ([]Endpoint, error) {
	return s.store.ListEndpointsForHost(ctx, hostID)
}

// CreateEndpoint создаёт эндпоинт (UPSERT на (host,path,method); всегда 201).
func (s *Service) CreateEndpoint(ctx context.Context, projectID, hostID int32, raw EndpointRaw, actorID int32) (*Endpoint, error) {
	if _, err := s.getHost(ctx, projectID, hostID); err != nil {
		return nil, err
	}
	payload := buildEndpointPayload(raw)
	if err := applyRawRequestPayload(payload); err != nil {
		return nil, err
	}
	applyStructuredRequestPayload(payload)
	if !nonNil(payload, "request_headers") {
		payload["request_headers"] = []header{}
	}

	path := getStr(payload, "path")
	method := getStrPtr(payload, "method")
	dup, err := s.store.FindEndpointDup(ctx, hostID, path, method, 0)
	if err != nil {
		return nil, err
	}
	if dup != nil {
		merged := mergeEndpoint(dup, payload)
		updated, err := s.store.UpdateEndpoint(ctx, merged)
		if err != nil {
			return nil, err
		}
		s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "endpoint", EntityID: &updated.ID})
		// TODO(phase2): ws broadcast (endpoint updated)
		return updated, nil
	}
	created, err := s.store.InsertEndpoint(ctx, NewEndpoint{
		HostID:             hostID,
		Path:               path,
		Method:             method,
		Description:        getStrPtr(payload, "description"),
		QueryParams:        qpBytes(payload),
		RequestBody:        getStrPtr(payload, "request_body"),
		RequestContentType: getStrPtr(payload, "request_content_type"),
		RequestHeaders:     hdrBytes(payload),
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "CREATE", EntityType: "endpoint", EntityID: &created.ID})
	// TODO(phase2): ws broadcast (endpoint created)
	return created, nil
}

// UpdateEndpoint обновляет эндпоинт (коллизия (path,method) → 409).
func (s *Service) UpdateEndpoint(ctx context.Context, projectID, hostID, endpointID int32, raw EndpointRaw, actorID int32) (*Endpoint, error) {
	if _, err := s.getHost(ctx, projectID, hostID); err != nil {
		return nil, err
	}
	payload := buildEndpointPayload(raw)
	if err := applyRawRequestPayload(payload); err != nil {
		return nil, err
	}
	applyStructuredRequestPayload(payload)

	endpoint, err := s.store.GetEndpointForHost(ctx, hostID, endpointID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Endpoint не найден")
	}
	if err != nil {
		return nil, err
	}

	nextPath := endpoint.Path
	if nonNil(payload, "path") {
		nextPath = getStr(payload, "path")
	}
	nextMethod := endpoint.Method
	if nonNil(payload, "method") {
		nextMethod = getStrPtr(payload, "method")
	}
	dup, err := s.store.FindEndpointDup(ctx, hostID, nextPath, nextMethod, endpointID)
	if err != nil {
		return nil, err
	}
	if dup != nil {
		return nil, apperr.Conflict("Эндпоинт с таким методом и path уже существует")
	}

	final := UpdateEndpointParams{
		ID:                 endpoint.ID,
		Path:               endpoint.Path,
		Method:             endpoint.Method,
		Description:        endpoint.Description,
		QueryParams:        endpoint.QueryParams,
		RequestBody:        endpoint.RequestBody,
		RequestContentType: endpoint.RequestContentType,
		RequestHeaders:     endpoint.RequestHeaders,
	}
	if nonNil(payload, "path") {
		final.Path = getStr(payload, "path")
	}
	if nonNil(payload, "method") {
		final.Method = getStrPtr(payload, "method")
	}
	if present(payload, "description") {
		final.Description = getStrPtr(payload, "description")
	}
	if present(payload, "query_params") {
		final.QueryParams = qpBytes(payload)
	}
	if present(payload, "request_body") {
		final.RequestBody = getStrPtr(payload, "request_body")
	}
	if present(payload, "request_content_type") {
		final.RequestContentType = getStrPtr(payload, "request_content_type")
	}
	if present(payload, "request_headers") {
		final.RequestHeaders = hdrBytes(payload)
	}
	updated, err := s.store.UpdateEndpoint(ctx, final)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "UPDATE", EntityType: "endpoint", EntityID: &updated.ID})
	// TODO(phase2): ws broadcast (endpoint updated)
	return updated, nil
}

// DeleteEndpoint удаляет эндпоинт.
func (s *Service) DeleteEndpoint(ctx context.Context, projectID, hostID, endpointID, actorID int32) error {
	endpoint, err := s.store.GetEndpointForHost(ctx, hostID, endpointID)
	if errors.Is(err, ErrNoRows) {
		return apperr.NotFound("Endpoint не найден")
	}
	if err != nil {
		return err
	}
	label := ""
	if endpoint.Method != nil {
		label = *endpoint.Method
	}
	label = strings.TrimSpace(label + " " + endpoint.Path)
	details := mustJSON(map[string]any{"project_id": itoa(projectID), "endpoint": label})
	if err := s.store.DeleteEndpoint(ctx, endpoint.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actorID, Action: "DELETE", EntityType: "endpoint", EntityID: &endpoint.ID, Details: details})
	// TODO(phase2): ws broadcast (endpoint deleted)
	return nil
}

// buildEndpointPayload переводит EndpointRaw в map с семантикой «ключ присутствует».
func buildEndpointPayload(raw EndpointRaw) map[string]any {
	p := map[string]any{}
	set := func(key string, val any) {
		if raw.Present[key] {
			p[key] = val
		}
	}
	set("path", strAny(raw.Path))
	set("method", strAny(raw.Method))
	set("description", strAny(raw.Description))
	set("request_raw", strAny(raw.RequestRaw))
	if raw.Present["query_params"] {
		p["query_params"] = qpAny(raw.QueryParams)
	}
	set("request_body", strAny(raw.RequestBody))
	set("request_content_type", strAny(raw.RequestContentType))
	if raw.Present["request_headers"] {
		p["request_headers"] = hdrAny(raw.RequestHeaders)
	}
	return p
}

// mergeEndpoint — _merge_endpoint_fields: заполняет только пустые поля существующего.
func mergeEndpoint(existing *Endpoint, payload map[string]any) UpdateEndpointParams {
	out := UpdateEndpointParams{
		ID:                 existing.ID,
		Path:               existing.Path,
		Method:             existing.Method,
		Description:        existing.Description,
		QueryParams:        existing.QueryParams,
		RequestBody:        existing.RequestBody,
		RequestContentType: existing.RequestContentType,
		RequestHeaders:     existing.RequestHeaders,
	}
	if isEmptyStrPtr(existing.Description) && strTruthy(payload, "description") {
		out.Description = getStrPtr(payload, "description")
	}
	if isEmptyJSON(existing.QueryParams) && len(getQP(payload)) > 0 {
		out.QueryParams = qpBytes(payload)
	}
	if isEmptyStrPtr(existing.RequestBody) && strTruthy(payload, "request_body") {
		out.RequestBody = getStrPtr(payload, "request_body")
	}
	if isEmptyStrPtr(existing.RequestContentType) && strTruthy(payload, "request_content_type") {
		out.RequestContentType = getStrPtr(payload, "request_content_type")
	}
	if isEmptyJSON(existing.RequestHeaders) && len(getHdr(payload)) > 0 {
		out.RequestHeaders = hdrBytes(payload)
	}
	return out
}

// ─────────────────────────── чистая логика: IP-нормализация ───────────────────────────

// normalizeHostIPEntries — порт _normalize_host_ip_entries (дедуп, ровно один primary).
func normalizeHostIPEntries(primaryIP *string, rawEntries []RawIPEntry) []IPEntry {
	entries := []IPEntry{}
	seen := map[string]bool{}
	add := func(ip *string, label *string, isPrimary bool) {
		value := ""
		if ip != nil {
			value = strings.TrimSpace(*ip)
		}
		if value == "" || seen[value] {
			return
		}
		seen[value] = true
		entries = append(entries, IPEntry{IPAddress: value, Label: label, IsPrimary: isPrimary})
	}
	for _, raw := range rawEntries {
		add(raw.IPAddress, raw.Label, raw.IsPrimary)
	}
	if primaryIP != nil && *primaryIP != "" {
		primary := strings.TrimSpace(*primaryIP)
		matched := false
		for i := range entries {
			if entries[i].IPAddress == primary {
				entries[i].IsPrimary = true
				matched = true
			} else {
				entries[i].IsPrimary = false
			}
		}
		if !matched {
			entries = append([]IPEntry{{IPAddress: primary, IsPrimary: true}}, entries...)
		}
	}
	primarySeen := false
	for i := range entries {
		if entries[i].IsPrimary && !primarySeen {
			primarySeen = true
		} else {
			entries[i].IsPrimary = false
		}
	}
	if len(entries) > 0 && !primarySeen {
		entries[0].IsPrimary = true
	}
	return entries
}

// primaryMirror — hosts.ip_address зеркалит primary IP (или первый, или nil).
func primaryMirror(entries []IPEntry) *string {
	for _, e := range entries {
		if e.IsPrimary {
			v := e.IPAddress
			return &v
		}
	}
	if len(entries) > 0 {
		v := entries[0].IPAddress
		return &v
	}
	return nil
}

// ─────────────────────────── чистая логика: endpoint-санитизация ───────────────────────────

var (
	reSlashes = regexp.MustCompile(`/{2,}`)
	reUUIDSeg = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	reBlank   = regexp.MustCompile(`\n\s*\n`)
)

var httpHeaderDrop = map[string]bool{
	"referer": true, "referrer": true, "connection": true, "accept-encoding": true,
	"accept-language": true, "sec-fetch-dest": true, "sec-fetch-mode": true,
	"sec-fetch-site": true, "sec-fetch-user": true, "sec-ch-ua": true,
	"sec-ch-ua-mobile": true, "sec-ch-ua-platform": true, "user-agent": true, "host": true,
}

var methodsWithoutBody = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true, "DELETE": true}

var rawAllowedMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "HEAD": true, "OPTIONS": true,
}

// normalizeEndpointPath — порт _normalize_endpoint_path.
func normalizeEndpointPath(pathValue string) string {
	pathOnly, _ := parseRequestTargetToken(pathValue)
	base := pathOnly
	if base == "" {
		base = "/"
	}
	base = strings.TrimSpace(base)
	if base == "" {
		base = "/"
	}
	normalized := reSlashes.ReplaceAllString(base, "/")
	if !strings.HasPrefix(normalized, "/") {
		normalized = "/" + normalized
	}
	if normalized != "/" && strings.HasSuffix(normalized, "/") {
		normalized = normalized[:len(normalized)-1]
	}
	segments := []string{}
	for _, seg := range strings.Split(normalized, "/") {
		if seg == "" {
			continue
		}
		if reUUIDSeg.MatchString(seg) {
			seg = "{UUID}"
		}
		segments = append(segments, seg)
	}
	if len(segments) == 0 {
		return "/"
	}
	return "/" + strings.Join(segments, "/")
}

// parseRequestTargetToken — порт _parse_request_target_token.
func parseRequestTargetToken(token string) (string, [][2]string) {
	token = strings.TrimSpace(token)
	var raw string
	if strings.HasPrefix(token, "http://") || strings.HasPrefix(token, "https://") {
		raw = token
	} else if strings.HasPrefix(token, "/") {
		raw = "http://stub.local" + token
	} else {
		raw = "http://stub.local/" + token
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/", nil
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return path, parseQSL(u.RawQuery)
}

// parseQSL — порт parse_qsl(keep_blank_values=True) с сохранением порядка.
func parseQSL(rawQuery string) [][2]string {
	out := [][2]string{}
	if rawQuery == "" {
		return out
	}
	for _, seg := range strings.Split(rawQuery, "&") {
		if seg == "" {
			continue
		}
		k, v, _ := strings.Cut(seg, "=")
		kk, err := url.QueryUnescape(k)
		if err != nil {
			kk = k
		}
		vv, err := url.QueryUnescape(v)
		if err != nil {
			vv = v
		}
		out = append(out, [2]string{kk, vv})
	}
	return out
}

func normalizeQueryParams(raw []qparam) []qparam {
	out := []qparam{}
	for _, item := range raw {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		var value *string
		if item.Value != nil {
			v := *item.Value
			value = &v
		}
		var desc *string
		if item.Description != nil {
			d := strings.TrimSpace(*item.Description)
			if d != "" {
				desc = &d
			}
		}
		out = append(out, qparam{Name: name, Value: value, Required: item.Required, Description: desc})
	}
	return out
}

func normalizeHeaders(raw []header) []header {
	out := []header{}
	for _, item := range raw {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		out = append(out, header{Name: name, Value: item.Value})
	}
	return out
}

func sanitizeParsedHeaderPairs(pairs [][2]string) []header {
	out := []header{}
	hadCookie := false
	for _, p := range pairs {
		ln := strings.ToLower(strings.TrimSpace(p[0]))
		if httpHeaderDrop[ln] {
			continue
		}
		if ln == "cookie" {
			hadCookie = true
			continue
		}
		if ln == "authorization" {
			out = append(out, header{Name: "Authorization", Value: "{YOUR_CREDENTIALS_HERE}"})
			continue
		}
		if ln == "content-type" {
			continue
		}
		out = append(out, header{Name: strings.TrimSpace(p[0]), Value: strings.TrimSpace(p[1])})
	}
	if hadCookie {
		out = append(out, header{Name: "Cookie", Value: "{YOUR_TOKENS_HERE}"})
	}
	return out
}

func sanitizeStoredHeaderItems(raw []header) []header {
	pairs := [][2]string{}
	for _, item := range raw {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		pairs = append(pairs, [2]string{name, item.Value})
	}
	return sanitizeParsedHeaderPairs(pairs)
}

// applyStructuredRequestPayload — порт _apply_structured_request_payload.
func applyStructuredRequestPayload(payload map[string]any) {
	if nonNil(payload, "path") {
		payload["path"] = normalizeEndpointPath(getStr(payload, "path"))
	}
	if present(payload, "query_params") {
		payload["query_params"] = normalizeQueryParams(getQP(payload))
	}
	if nonNil(payload, "request_headers") {
		payload["request_headers"] = sanitizeStoredHeaderItems(normalizeHeaders(getHdr(payload)))
	}
	if nonNil(payload, "request_body") {
		rb := getStr(payload, "request_body")
		if strings.TrimSpace(rb) != "" {
			payload["request_body"] = rb
		} else {
			payload["request_body"] = nil
		}
	}
	if nonNil(payload, "request_content_type") {
		ct := strings.TrimSpace(getStr(payload, "request_content_type"))
		if ct != "" {
			payload["request_content_type"] = ct
		} else {
			payload["request_content_type"] = nil
		}
	}
}

// applyRawRequestPayload — порт _apply_raw_request_payload.
func applyRawRequestPayload(payload map[string]any) error {
	rawStr := getStr(payload, "request_raw")
	if rawStr == "" {
		delete(payload, "request_raw")
		return nil
	}
	raw := strings.ReplaceAll(rawStr, "\r", "")
	parts := reBlank.Split(raw, 2)
	headerBlock := parts[0]
	body := ""
	if len(parts) > 1 {
		body = parts[1]
	}
	headerLines := strings.Split(headerBlock, "\n")
	if len(headerLines) == 0 || strings.TrimSpace(headerLines[0]) == "" {
		return apperr.Validation("request_raw пустой")
	}
	requestLine := strings.Fields(headerLines[0])
	if len(requestLine) < 3 {
		return apperr.Validation("request_raw должен содержать request line вида 'METHOD /path HTTP/1.1'")
	}
	method := strings.ToUpper(requestLine[0])
	pathValue := requestLine[1]
	httpPart := strings.ToUpper(requestLine[2])
	if !rawAllowedMethods[method] {
		return apperr.Validation("request_raw содержит неподдерживаемый HTTP-метод")
	}
	if !strings.HasPrefix(httpPart, "HTTP/") {
		return apperr.Validation("request_raw должен содержать HTTP-версию в request line")
	}
	pathOnly, queryPairs := parseRequestTargetToken(pathValue)
	payload["method"] = method
	payload["path"] = normalizeEndpointPath(pathOnly)
	if !present(payload, "query_params") || len(getQP(payload)) == 0 {
		qps := make([]qparam, 0, len(queryPairs))
		for _, pair := range queryPairs {
			v := pair[1]
			qps = append(qps, qparam{Name: pair[0], Value: &v, Required: false, Description: nil})
		}
		payload["query_params"] = qps
	}
	headerPairs := [][2]string{}
	for _, line := range headerLines[1:] {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, ":") {
			continue
		}
		hName, hVal, _ := strings.Cut(line, ":")
		headerPairs = append(headerPairs, [2]string{strings.TrimSpace(hName), hVal})
	}
	var contentType *string
	for _, p := range headerPairs {
		if strings.ToLower(p[0]) == "content-type" {
			ct := strings.TrimSpace(p[1])
			if ct != "" {
				contentType = &ct
			}
			break
		}
	}
	if !nonNil(payload, "request_body") && strings.TrimSpace(body) != "" {
		payload["request_body"] = body
	}
	if !nonNil(payload, "request_content_type") && contentType != nil {
		payload["request_content_type"] = *contentType
	}
	if !present(payload, "request_headers") || len(getHdr(payload)) == 0 {
		payload["request_headers"] = sanitizeParsedHeaderPairs(headerPairs)
	}
	if methodsWithoutBody[method] {
		payload["request_body"] = nil
		payload["request_content_type"] = nil
	}
	delete(payload, "request_raw")
	return nil
}

// ─────────────────────────── map/enum helpers ───────────────────────────

func present(p map[string]any, k string) bool { _, ok := p[k]; return ok }

func nonNil(p map[string]any, k string) bool {
	v, ok := p[k]
	return ok && v != nil
}

func getStr(p map[string]any, k string) string {
	if v, ok := p[k]; ok && v != nil {
		if s, ok2 := v.(string); ok2 {
			return s
		}
	}
	return ""
}

func getStrPtr(p map[string]any, k string) *string {
	if v, ok := p[k]; ok && v != nil {
		if s, ok2 := v.(string); ok2 {
			ss := s
			return &ss
		}
	}
	return nil
}

func getQP(p map[string]any) []qparam {
	if v, ok := p["query_params"]; ok && v != nil {
		if q, ok2 := v.([]qparam); ok2 {
			return q
		}
	}
	return nil
}

func getHdr(p map[string]any) []header {
	if v, ok := p["request_headers"]; ok && v != nil {
		if h, ok2 := v.([]header); ok2 {
			return h
		}
	}
	return nil
}

func qpBytes(p map[string]any) []byte {
	q := getQP(p)
	if len(q) == 0 {
		return []byte("[]")
	}
	b, _ := json.Marshal(q)
	return b
}

func hdrBytes(p map[string]any) []byte {
	h := getHdr(p)
	if len(h) == 0 {
		return []byte("[]")
	}
	b, _ := json.Marshal(h)
	return b
}

func strAny(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func qpAny(in *[]QueryParamInput) any {
	if in == nil {
		return nil
	}
	out := make([]qparam, 0, len(*in))
	for _, q := range *in {
		out = append(out, qparam{Name: q.Name, Value: q.Value, Required: q.Required, Description: q.Description})
	}
	return out
}

func hdrAny(in *[]HeaderInput) any {
	if in == nil {
		return nil
	}
	out := make([]header, 0, len(*in))
	for _, h := range *in {
		out = append(out, header{Name: h.Name, Value: h.Value})
	}
	return out
}

func strTruthy(p map[string]any, k string) bool { return nonNil(p, k) && getStr(p, k) != "" }

func isEmptyStrPtr(s *string) bool { return s == nil || *s == "" }

func isEmptyJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "[]" || s == "{}" || s == `""`
}

func normalizeStatus(v *string) (string, error) {
	if v == nil || *v == "" {
		return HostStatusUnknown, nil
	}
	up := strings.ToUpper(*v)
	if !validHostStatus[up] {
		return "", apperr.Validation("Недопустимый статус хоста")
	}
	return up, nil
}

func normalizeOsType(v *string) (string, error) {
	if v == nil || *v == "" {
		return OsTypeUnknown, nil
	}
	up := strings.ToUpper(*v)
	if !validOsType[up] {
		return "", apperr.Validation("Недопустимый тип ОС")
	}
	return up, nil
}

func normalizeProtocol(v *string) (string, error) {
	if v == nil || *v == "" {
		return ProtocolTCP, nil
	}
	up := strings.ToUpper(*v)
	if !validProtocol[up] {
		return "", apperr.Validation("Недопустимый протокол")
	}
	return up, nil
}

func normalizePortState(v *string) (string, error) {
	if v == nil || *v == "" {
		return PortStateOpen, nil
	}
	up := strings.ToUpper(*v)
	if !validPortState[up] {
		return "", apperr.Validation("Недопустимое состояние порта")
	}
	return up, nil
}

func validatePortNumber(n int32) error {
	if n < 1 || n > 65535 {
		return apperr.Validation("port_number должен быть от 1 до 65535")
	}
	return nil
}

func itoa(v int32) string {
	return strconv.Itoa(int(v))
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
