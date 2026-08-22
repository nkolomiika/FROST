package http

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/inventory"
	"github.com/nkolomiika/frost/internal/app/projects"
	"github.com/nkolomiika/frost/internal/apperr"
)

// maxImportUpload — предел тела multipart-импорта (PCF/OpenAPI ≤ 2 МБ + запас).
const maxImportUpload = 8 << 20

// InventoryHandler обслуживает контекст активов (/api/v1 hosts/ports/services/
// endpoints + import/export). Доступ к проекту — через projects.Service.
type InventoryHandler struct {
	svc         *inventory.Service
	authz       *projects.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewInventoryHandler собирает обработчик.
func NewInventoryHandler(svc *inventory.Service, authz *projects.Service, authSvc *auth.Service, csrfOrigins []string) *InventoryHandler {
	return &InventoryHandler{svc: svc, authz: authz, auth: authSvc, csrfOrigins: csrfOrigins}
}

// Register монтирует роуты. Роуты регистрируются напрямую (r.Group, полные пути),
// а не через r.Route("/api/v1", …): контекст projects уже держит mount на
// «/api/v1/projects», и второй перекрывающий mount перехватил бы эти пути (404).
// requireProjectAccessFor(h.authz) — per-route middleware после requireAuth;
// мутирующие методы дополнительно проходят enforceCSRF.
func (h *InventoryHandler) Register(r chi.Router) {
	pa := requireProjectAccessFor(h.authz)
	const base = "/api/v1/projects/{project_id}"
	r.Group(func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))

		// hosts
		ar.With(pa).Get(base+"/hosts", h.listHosts)
		ar.With(pa).Post(base+"/hosts", h.createHost)
		ar.With(pa).Post(base+"/hosts/bulk-delete", h.bulkDeleteHosts)
		ar.With(pa).Get(base+"/hosts/{host_id}", h.getHost)
		ar.With(pa).Put(base+"/hosts/{host_id}", h.updateHost)
		ar.With(pa).Delete(base+"/hosts/{host_id}", h.deleteHost)

		// ports
		ar.With(pa).Get(base+"/hosts/{host_id}/ports", h.listPorts)
		ar.With(pa).Post(base+"/hosts/{host_id}/ports", h.createPort)
		ar.With(pa).Get(base+"/hosts/{host_id}/ports/{port_id}", h.getPort)
		ar.With(pa).Put(base+"/hosts/{host_id}/ports/{port_id}", h.updatePort)
		ar.With(pa).Delete(base+"/hosts/{host_id}/ports/{port_id}", h.deletePort)

		// services
		ar.With(pa).Get(base+"/hosts/{host_id}/ports/{port_id}/services", h.listServices)
		ar.With(pa).Post(base+"/hosts/{host_id}/ports/{port_id}/services", h.createService)
		ar.With(pa).Put(base+"/hosts/{host_id}/ports/{port_id}/services/{service_id}", h.updateService)
		ar.With(pa).Delete(base+"/hosts/{host_id}/ports/{port_id}/services/{service_id}", h.deleteService)

		// endpoints
		ar.With(pa).Post(base+"/endpoints/bulk-delete", h.bulkDeleteEndpoints)
		ar.With(pa).Get(base+"/hosts/{host_id}/endpoints", h.listEndpoints)
		ar.With(pa).Post(base+"/hosts/{host_id}/endpoints", h.createEndpoint)
		ar.With(pa).Put(base+"/hosts/{host_id}/endpoints/{endpoint_id}", h.updateEndpoint)
		ar.With(pa).Delete(base+"/hosts/{host_id}/endpoints/{endpoint_id}", h.deleteEndpoint)

		// import / export
		ar.With(pa).Post(base+"/hosts/{host_id}/import-openapi", h.importOpenAPI)
		ar.With(pa).Get(base+"/hosts/{host_id}/export-openapi", h.exportOpenAPI)
		ar.With(pa).Post(base+"/import", h.importProject)
	})
}

// ─────────────────────────── hosts ───────────────────────────

func (h *InventoryHandler) listHosts(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	page := intQuery(r, "page", 1, 1, 1_000_000)
	size := intQuery(r, "size", 20, 1, 200)
	statusFilter := strings.TrimSpace(r.URL.Query().Get("status"))
	origin := strings.TrimSpace(r.URL.Query().Get("origin"))
	if origin == "" {
		origin = "host"
	}
	if origin != "host" && origin != "ip" && origin != "all" {
		writeError(w, apperr.Validation("Некорректный origin"))
		return
	}
	aggs, total, err := h.svc.ListHosts(r.Context(), pid, page, size, statusFilter, origin)
	if err != nil {
		writeError(w, err)
		return
	}
	items := make([]map[string]any, 0, len(aggs))
	for i := range aggs {
		items = append(items, hostListItem(&aggs[i]))
	}
	writeJSON(w, http.StatusOK, paginated(items, total, page, size))
}

func (h *InventoryHandler) createHost(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	var req apiv1.HostCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	in := inventory.HostCreateInput{
		IPAddress: req.IpAddress,
		Hostname:  req.Hostname,
		Notes:     req.Notes,
		Status:    hostStatusLower(req.Status),
		OsType:    osTypeLower(req.OsType),
	}
	if req.IpAddresses != nil {
		in.IPAddresses = *req.IpAddresses
	}
	agg, err := h.svc.CreateHost(r.Context(), pid, in, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, hostOut(agg))
}

func (h *InventoryHandler) getHost(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	agg, err := h.svc.GetHost(r.Context(), pid, hid)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hostDetail(agg))
}

func (h *InventoryHandler) updateHost(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	keys, err := bodyKeys(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.HostUpdate
	if err := json.Unmarshal(keys.body, &req); err != nil {
		writeError(w, apperr.Validation("Некорректное тело запроса"))
		return
	}
	in := inventory.HostUpdateInput{
		IPAddressPresent:   keys.has("ip_address"),
		IPAddress:          req.IpAddress,
		IPAddressesPresent: keys.has("ip_addresses"),
		Hostname:           req.Hostname,
		Notes:              req.Notes,
		Status:             hostStatusLower(req.Status),
		OsType:             osTypeLower(req.OsType),
	}
	if req.IpAddresses != nil {
		for _, e := range *req.IpAddresses {
			ip := e.IpAddress
			entry := inventory.RawIPEntry{IPAddress: &ip, Label: e.Label}
			if e.IsPrimary != nil {
				entry.IsPrimary = *e.IsPrimary
			}
			in.IPAddresses = append(in.IPAddresses, entry)
		}
	}
	agg, err := h.svc.UpdateHost(r.Context(), pid, hid, in, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hostOut(agg))
}

func (h *InventoryHandler) deleteHost(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteHost(r.Context(), pid, hid, actorFrom(r).ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// bulkDeleteHosts удаляет хосты проекта по списку id (POST .../hosts/bulk-delete,
// тело {"ids":[…]}). Отдаёт {"deleted":N}. Скоуп проекта в SQL — чужие id не рушат
// запрос и не удаляются.
func (h *InventoryHandler) bulkDeleteHosts(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	var req bulkIDsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	ids, err := dedupIDs(req.IDs)
	if err != nil {
		writeError(w, err)
		return
	}
	deleted, err := h.svc.DeleteHostsBulk(r.Context(), pid, ids, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
}

// bulkDeleteEndpoints удаляет эндпоинты по списку id (POST .../endpoints/bulk-delete,
// тело {"ids":[…]}). Отдаёт {"deleted":N}. Удаляются только эндпоинты, чей host
// принадлежит проекту.
func (h *InventoryHandler) bulkDeleteEndpoints(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	var req bulkIDsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	ids, err := dedupIDs(req.IDs)
	if err != nil {
		writeError(w, err)
		return
	}
	deleted, err := h.svc.DeleteEndpointsBulk(r.Context(), pid, ids, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"deleted": deleted})
}

// ─────────────────────────── ports ───────────────────────────

func (h *InventoryHandler) listPorts(w http.ResponseWriter, r *http.Request) {
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	ports, err := h.svc.ListPorts(r.Context(), hid)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.PortOut, 0, len(ports))
	for i := range ports {
		out = append(out, portOut(&ports[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *InventoryHandler) createPort(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.PortCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	in := inventory.PortCreateInput{
		IPAddressID: int32(req.IpAddressId),
		PortNumber:  int32(req.PortNumber),
		Protocol:    protocolLower(req.Protocol),
		State:       portStateLower(req.State),
		HTTPStatus:  intPtr32(req.HttpStatus),
	}
	port, err := h.svc.CreatePort(r.Context(), pid, hid, in, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, portOut(port))
}

func (h *InventoryHandler) getPort(w http.ResponseWriter, r *http.Request) {
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	pid2, err := pathInt32(r, "port_id")
	if err != nil {
		writeError(w, err)
		return
	}
	port, err := h.svc.GetPort(r.Context(), hid, pid2)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, portOut(port))
}

func (h *InventoryHandler) updatePort(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	portID, err := pathInt32(r, "port_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.PortUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	in := inventory.PortUpdateInput{
		IPAddressID: intPtr32(req.IpAddressId),
		PortNumber:  intPtr32(req.PortNumber),
		Protocol:    protocolLower(req.Protocol),
		State:       portStateLower(req.State),
		HTTPStatus:  intPtr32(req.HttpStatus),
	}
	port, err := h.svc.UpdatePort(r.Context(), pid, hid, portID, in, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, portOut(port))
}

func (h *InventoryHandler) deletePort(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	portID, err := pathInt32(r, "port_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeletePort(r.Context(), pid, hid, portID, actorFrom(r).ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── services ───────────────────────────

func (h *InventoryHandler) listServices(w http.ResponseWriter, r *http.Request) {
	portID, err := pathInt32(r, "port_id")
	if err != nil {
		writeError(w, err)
		return
	}
	services, err := h.svc.ListServices(r.Context(), portID)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.ServiceOut, 0, len(services))
	for i := range services {
		out = append(out, serviceOut(&services[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *InventoryHandler) createService(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	portID, err := pathInt32(r, "port_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ServiceCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	svc, err := h.svc.CreateService(r.Context(), pid, hid, portID, req.Name, req.Version, req.Banner, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, serviceOut(svc))
}

func (h *InventoryHandler) updateService(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	portID, err := pathInt32(r, "port_id")
	if err != nil {
		writeError(w, err)
		return
	}
	serviceID, err := pathInt32(r, "service_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.ServiceUpdate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	svc, err := h.svc.UpdateService(r.Context(), pid, hid, portID, serviceID, req.Name, req.Version, req.Banner, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, serviceOut(svc))
}

func (h *InventoryHandler) deleteService(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	portID, err := pathInt32(r, "port_id")
	if err != nil {
		writeError(w, err)
		return
	}
	serviceID, err := pathInt32(r, "service_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteService(r.Context(), pid, portID, serviceID, actorFrom(r).ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── endpoints ───────────────────────────

func (h *InventoryHandler) listEndpoints(w http.ResponseWriter, r *http.Request) {
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	endpoints, err := h.svc.ListEndpoints(r.Context(), hid)
	if err != nil {
		writeError(w, err)
		return
	}
	out := make([]apiv1.EndpointOut, 0, len(endpoints))
	for i := range endpoints {
		out = append(out, endpointOut(&endpoints[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *InventoryHandler) createEndpoint(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.EndpointCreate
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	raw := endpointCreateRaw(req)
	ep, err := h.svc.CreateEndpoint(r.Context(), pid, hid, raw, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, endpointOut(ep))
}

func (h *InventoryHandler) updateEndpoint(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	eid, err := pathInt32(r, "endpoint_id")
	if err != nil {
		writeError(w, err)
		return
	}
	keys, err := bodyKeys(r)
	if err != nil {
		writeError(w, err)
		return
	}
	var req apiv1.EndpointUpdate
	if err := json.Unmarshal(keys.body, &req); err != nil {
		writeError(w, apperr.Validation("Некорректное тело запроса"))
		return
	}
	raw := endpointUpdateRaw(req, keys)
	ep, err := h.svc.UpdateEndpoint(r.Context(), pid, hid, eid, raw, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, endpointOut(ep))
}

func (h *InventoryHandler) deleteEndpoint(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	eid, err := pathInt32(r, "endpoint_id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.DeleteEndpoint(r.Context(), pid, hid, eid, actorFrom(r).ID); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─────────────────────────── import / export ───────────────────────────

func (h *InventoryHandler) importOpenAPI(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	filename, payload, err := readUploadFile(r)
	if err != nil {
		writeError(w, err)
		return
	}
	if filename == "" {
		writeError(w, apperr.Validation("Нужно выбрать Swagger/OpenAPI файл"))
		return
	}
	result, err := h.svc.ImportOpenAPI(r.Context(), pid, hid, payload, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, openAPIImportResultOut(result))
}

func (h *InventoryHandler) exportOpenAPI(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	hid, err := pathInt32(r, "host_id")
	if err != nil {
		writeError(w, err)
		return
	}
	document, err := h.svc.ExportOpenAPI(r.Context(), pid, hid)
	if err != nil {
		writeError(w, err)
		return
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\"openapi-"+itoa32(hid)+".json\"")
	writeJSON(w, http.StatusOK, document)
}

func (h *InventoryHandler) importProject(w http.ResponseWriter, r *http.Request) {
	pid := projectFromContext(r.Context()).ID
	_, payload, err := readUploadFile(r)
	if err != nil {
		writeError(w, err)
		return
	}
	result, err := h.svc.ImportJSON(r.Context(), pid, payload, actorFrom(r).ID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, importResultOut(result))
}

// readUploadFile читает multipart-поле `file`.
func readUploadFile(r *http.Request) (string, []byte, error) {
	if err := r.ParseMultipartForm(maxImportUpload); err != nil {
		return "", nil, apperr.Validation("Некорректная multipart-форма")
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		return "", nil, apperr.Validation("Нужно приложить файл в поле 'file'")
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxImportUpload))
	if err != nil {
		return "", nil, apperr.Validation("Не удалось прочитать файл")
	}
	name := ""
	if header != nil {
		name = header.Filename
	}
	return name, data, nil
}

// bodyKey — прочитанное тело запроса + набор присутствующих ключей верхнего уровня.
type bodyKey struct {
	body []byte
	keys map[string]bool
}

func (b bodyKey) has(k string) bool { return b.keys[k] }

// bodyKeys читает тело один раз и извлекает ключи верхнего уровня (для точного
// повторения model_dump(exclude_unset) — различаем «поле прислано» и «нет»).
func bodyKeys(r *http.Request) (bodyKey, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return bodyKey{}, apperr.Validation("Некорректное тело запроса")
	}
	keys := map[string]bool{}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return bodyKey{body: []byte("{}"), keys: keys}, nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return bodyKey{}, apperr.Validation("Некорректное тело запроса")
	}
	for k := range raw {
		keys[k] = true
	}
	return bodyKey{body: data, keys: keys}, nil
}
