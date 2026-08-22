package inventory

import "context"

// fakeInvStore — минимальная in-memory реализация Store для проверки логики уровня
// сервиса (дедуп эндпоинтов, парсинг OpenAPI, экспорт). Компаундные операции
// (UpsertOpenAPIEndpoints/ImportPCF) выполняются в реальном адаптере в транзакции;
// здесь они сведены к захвату входных данных и заранее заданным счётчикам.
type fakeInvStore struct {
	host *Host

	// endpoint dup / create / update
	dupEndpoint     *Endpoint
	findDupPath     string
	findDupMethod   *string
	insertCalled    bool
	updatedParams   UpdateEndpointParams
	updateWasCalled bool

	// openapi upsert
	upsertEps     []EndpointImport
	upsertCreated int
	upsertSkipped int
	upsertErr     error

	// export
	orderedEndpoints []Endpoint

	// list hosts
	lastListParams HostListParams
}

func (f *fakeInvStore) GetHost(context.Context, int32, int32) (*Host, error) {
	if f.host == nil {
		return nil, ErrNoRows
	}
	h := *f.host
	return &h, nil
}

func (f *fakeInvStore) FindEndpointDup(_ context.Context, _ int32, path string, method *string, _ int32) (*Endpoint, error) {
	f.findDupPath = path
	f.findDupMethod = method
	if f.dupEndpoint == nil {
		return nil, nil
	}
	e := *f.dupEndpoint
	return &e, nil
}

func (f *fakeInvStore) InsertEndpoint(_ context.Context, ne NewEndpoint) (*Endpoint, error) {
	f.insertCalled = true
	return &Endpoint{ID: 1, HostID: ne.HostID, Path: ne.Path, Method: ne.Method,
		Description: ne.Description, QueryParams: ne.QueryParams, RequestBody: ne.RequestBody,
		RequestContentType: ne.RequestContentType, RequestHeaders: ne.RequestHeaders}, nil
}

func (f *fakeInvStore) UpdateEndpoint(_ context.Context, p UpdateEndpointParams) (*Endpoint, error) {
	f.updatedParams = p
	f.updateWasCalled = true
	return &Endpoint{ID: p.ID, Path: p.Path, Method: p.Method, Description: p.Description,
		QueryParams: p.QueryParams, RequestBody: p.RequestBody, RequestContentType: p.RequestContentType,
		RequestHeaders: p.RequestHeaders}, nil
}

func (f *fakeInvStore) UpsertOpenAPIEndpoints(_ context.Context, _ int32, eps []EndpointImport) (int, int, error) {
	f.upsertEps = eps
	return f.upsertCreated, f.upsertSkipped, f.upsertErr
}

func (f *fakeInvStore) ListEndpointsForHostOrdered(context.Context, int32) ([]Endpoint, error) {
	return f.orderedEndpoints, nil
}

// ─────────────────── остальные методы Store — заглушки ───────────────────

func (f *fakeInvStore) ListHostsPage(_ context.Context, p HostListParams) ([]Host, int64, error) {
	f.lastListParams = p
	return nil, 0, nil
}
func (f *fakeInvStore) CreateHost(context.Context, NewHost, []IPEntry) (int32, error) { return 1, nil }
func (f *fakeInvStore) UpdateHost(context.Context, HostUpdateParams) error            { return nil }
func (f *fakeInvStore) DeleteHost(context.Context, int32, int32) error                { return nil }
func (f *fakeInvStore) BulkDeleteHosts(context.Context, int32, []int32) (int64, error) {
	return 0, nil
}
func (f *fakeInvStore) LoadTrees(context.Context, []Host) ([]HostAggregate, error) { return nil, nil }
func (f *fakeInvStore) GetHostIP(context.Context, int32, int32) (*HostIP, error) {
	return nil, ErrNoRows
}
func (f *fakeInvStore) ListProjectHosts(context.Context, int32) ([]Host, error) { return nil, nil }
func (f *fakeInvStore) ListPortsForHost(context.Context, int32) ([]Port, error) { return nil, nil }
func (f *fakeInvStore) GetPort(context.Context, int32, int32) (*Port, error)    { return nil, ErrNoRows }
func (f *fakeInvStore) FindPortDup(context.Context, int32, int32, string, int32) (bool, error) {
	return false, nil
}
func (f *fakeInvStore) InsertPort(context.Context, NewPort) (*Port, error) { return &Port{ID: 1}, nil }
func (f *fakeInvStore) UpdatePort(context.Context, UpdatePortParams) (*Port, error) {
	return &Port{ID: 1}, nil
}
func (f *fakeInvStore) DeletePort(context.Context, int32) error { return nil }
func (f *fakeInvStore) ListServicesForPort(context.Context, int32) ([]PortService, error) {
	return nil, nil
}
func (f *fakeInvStore) GetServiceForPort(context.Context, int32, int32) (*PortService, error) {
	return nil, ErrNoRows
}
func (f *fakeInvStore) InsertService(context.Context, int32, string, *string, *string) (*PortService, error) {
	return &PortService{ID: 1}, nil
}
func (f *fakeInvStore) UpdateService(context.Context, int32, string, *string, *string) (*PortService, error) {
	return &PortService{ID: 1}, nil
}
func (f *fakeInvStore) DeleteService(context.Context, int32) error { return nil }
func (f *fakeInvStore) ListEndpointsForHost(context.Context, int32) ([]Endpoint, error) {
	return nil, nil
}
func (f *fakeInvStore) GetEndpointForHost(context.Context, int32, int32) (*Endpoint, error) {
	return nil, ErrNoRows
}
func (f *fakeInvStore) DeleteEndpoint(context.Context, int32) error { return nil }
func (f *fakeInvStore) BulkDeleteEndpoints(context.Context, int32, []int32) (int64, error) {
	return 0, nil
}
func (f *fakeInvStore) ImportPCF(context.Context, int32, []PcfHost) (ImportResult, error) {
	return ImportResult{}, nil
}
func (f *fakeInvStore) InsertAudit(context.Context, AuditEntry) error { return nil }

var _ Store = (*fakeInvStore)(nil)
