// Package inventoryrepo — реализация порта inventory.Store поверх sqlc + pgxpool.
// Компаундные операции (создание/обновление хоста с заменой IP, импорт PCF и
// OpenAPI) выполняются в транзакции через r.tx.
package inventoryrepo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/inventory"
)

// Repo реализует inventory.Store.
type Repo struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// New создаёт репозиторий поверх пула соединений.
func New(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool, q: sqlc.New(pool)}
}

var _ inventory.Store = (*Repo)(nil)

func (r *Repo) tx(ctx context.Context, fn func(q *sqlc.Queries) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(r.q.WithTx(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func mapErr(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return inventory.ErrNoRows
	}
	return err
}

// ─────────────────────────── мапперы sqlc→домен ───────────────────────────

func mapHost(h sqlc.Host) inventory.Host {
	return inventory.Host{
		ID:        h.ID,
		ProjectID: h.ProjectID,
		IPAddress: pgconv.TextValPtr(h.IpAddress),
		Hostname:  pgconv.TextValPtr(h.Hostname),
		Status:    string(h.Status),
		OsType:    string(h.OsType),
		Notes:     pgconv.TextValPtr(h.Notes),
		Origin:    h.Origin,
		CreatedAt: pgconv.TsVal(h.CreatedAt),
		UpdatedAt: pgconv.TsVal(h.UpdatedAt),
	}
}

func mapHostIP(ip sqlc.HostIpAddress) inventory.HostIP {
	return inventory.HostIP{
		ID:           ip.ID,
		HostID:       ip.HostID,
		IPAddress:    ip.IpAddress,
		Label:        pgconv.TextValPtr(ip.Label),
		IsPrimary:    ip.IsPrimary,
		Hostnames:    ip.Hostnames,
		IsCloudflare: boolValPtr(ip.IsCloudflare),
		CreatedAt:    pgconv.TsVal(ip.CreatedAt),
		UpdatedAt:    pgconv.TsVal(ip.UpdatedAt),
	}
}

func mapPort(p sqlc.Port) inventory.Port {
	return inventory.Port{
		ID:          p.ID,
		HostID:      p.HostID,
		IPAddressID: p.IpAddressID,
		PortNumber:  p.PortNumber,
		Protocol:    string(p.Protocol),
		State:       string(p.State),
		HTTPStatus:  pgconv.Int4Val(p.HttpStatus),
		CreatedAt:   pgconv.TsVal(p.CreatedAt),
		UpdatedAt:   pgconv.TsVal(p.UpdatedAt),
	}
}

func mapService(s sqlc.Service) inventory.PortService {
	return inventory.PortService{
		ID:        s.ID,
		PortID:    s.PortID,
		Name:      s.Name,
		Version:   pgconv.TextValPtr(s.Version),
		Banner:    pgconv.TextValPtr(s.Banner),
		CreatedAt: pgconv.TsVal(s.CreatedAt),
		UpdatedAt: pgconv.TsVal(s.UpdatedAt),
	}
}

func mapEndpoint(e sqlc.Endpoint) inventory.Endpoint {
	return inventory.Endpoint{
		ID:                 e.ID,
		HostID:             e.HostID,
		Path:               e.Path,
		Method:             methodPtr(e.Method),
		Description:        pgconv.TextValPtr(e.Description),
		QueryParams:        e.QueryParams,
		RequestBody:        pgconv.TextValPtr(e.RequestBody),
		RequestContentType: pgconv.TextValPtr(e.RequestContentType),
		RequestHeaders:     e.RequestHeaders,
		CreatedAt:          pgconv.TsVal(e.CreatedAt),
		UpdatedAt:          pgconv.TsVal(e.UpdatedAt),
	}
}

// ─────────────────────────── hosts ───────────────────────────

func (r *Repo) ListHostsPage(ctx context.Context, p inventory.HostListParams) ([]inventory.Host, int64, error) {
	origin := pgconv.Text(p.Origin)
	status := nullStatus(p.Status)
	total, err := r.q.CountHosts(ctx, sqlc.CountHostsParams{ProjectID: p.ProjectID, Origin: origin, Status: status})
	if err != nil {
		return nil, 0, err
	}
	rows, err := r.q.ListHosts(ctx, sqlc.ListHostsParams{
		ProjectID: p.ProjectID, Origin: origin, Status: status, Offset: p.Offset, Lim: p.Limit,
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]inventory.Host, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapHost(row))
	}
	return out, total, nil
}

func (r *Repo) GetHost(ctx context.Context, projectID, hostID int32) (*inventory.Host, error) {
	h, err := r.q.GetHost(ctx, sqlc.GetHostParams{ID: hostID, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	host := mapHost(h)
	return &host, nil
}

func (r *Repo) ListProjectHosts(ctx context.Context, projectID int32) ([]inventory.Host, error) {
	rows, err := r.q.ListHosts(ctx, sqlc.ListHostsParams{ProjectID: projectID, Offset: 0, Lim: 1_000_000})
	if err != nil {
		return nil, err
	}
	out := make([]inventory.Host, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapHost(row))
	}
	return out, nil
}

func (r *Repo) CreateHost(ctx context.Context, nh inventory.NewHost, entries []inventory.IPEntry) (int32, error) {
	var hostID int32
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		host, err := q.InsertHost(ctx, sqlc.InsertHostParams{
			ProjectID: nh.ProjectID,
			IpAddress: pgconv.TextPtr(nh.IPAddress),
			Hostname:  pgconv.TextPtr(nh.Hostname),
			Status:    sqlc.HostStatus(nh.Status),
			OsType:    sqlc.HostOsType(nh.OsType),
			Notes:     pgconv.TextPtr(nh.Notes),
			Origin:    nh.Origin,
		})
		if err != nil {
			return err
		}
		hostID = host.ID
		for _, e := range entries {
			if _, err := q.InsertHostIP(ctx, sqlc.InsertHostIPParams{
				HostID:       host.ID,
				IpAddress:    e.IPAddress,
				Label:        pgconv.TextPtr(e.Label),
				IsPrimary:    e.IsPrimary,
				IsCloudflare: cfBoolForNew(e.IPAddress),
				Hostnames:    nil,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return hostID, nil
}

func (r *Repo) UpdateHost(ctx context.Context, p inventory.HostUpdateParams) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		if _, err := q.UpdateHost(ctx, sqlc.UpdateHostParams{
			ID:        p.HostID,
			IpAddress: pgconv.TextPtr(p.Fields.IPAddress),
			Hostname:  pgconv.TextPtr(p.Fields.Hostname),
			Status:    sqlc.HostStatus(p.Fields.Status),
			OsType:    sqlc.HostOsType(p.Fields.OsType),
			Notes:     pgconv.TextPtr(p.Fields.Notes),
		}); err != nil {
			return err
		}
		if !p.ReplaceIPs {
			return nil
		}
		existingRows, err := q.ListHostIPs(ctx, p.HostID)
		if err != nil {
			return err
		}
		existing := make(map[string]sqlc.HostIpAddress, len(existingRows))
		for _, row := range existingRows {
			existing[row.IpAddress] = row
		}
		desired := make(map[string]bool, len(p.Entries))
		for _, e := range p.Entries {
			desired[e.IPAddress] = true
		}
		for ip, row := range existing {
			if !desired[ip] {
				if err := q.DeleteHostIP(ctx, row.ID); err != nil {
					return err
				}
			}
		}
		for _, e := range p.Entries {
			row, ok := existing[e.IPAddress]
			if !ok {
				if _, err := q.InsertHostIP(ctx, sqlc.InsertHostIPParams{
					HostID:       p.HostID,
					IpAddress:    e.IPAddress,
					Label:        pgconv.TextPtr(e.Label),
					IsPrimary:    e.IsPrimary,
					IsCloudflare: cfBoolForNew(e.IPAddress),
					Hostnames:    nil,
				}); err != nil {
					return err
				}
				continue
			}
			cf := row.IsCloudflare
			if inventory.IsCloudflareIP(e.IPAddress) {
				cf = pgtype.Bool{Bool: true, Valid: true}
			}
			if err := q.UpdateHostIP(ctx, sqlc.UpdateHostIPParams{
				ID:           row.ID,
				Label:        pgconv.TextPtr(e.Label),
				IsPrimary:    e.IsPrimary,
				IsCloudflare: cf,
				Hostnames:    row.Hostnames,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Repo) DeleteHost(ctx context.Context, projectID, hostID int32) error {
	return r.q.DeleteHost(ctx, sqlc.DeleteHostParams{ID: hostID, ProjectID: projectID})
}

func (r *Repo) BulkDeleteHosts(ctx context.Context, projectID int32, ids []int32) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	return r.q.BulkDeleteHosts(ctx, sqlc.BulkDeleteHostsParams{ProjectID: projectID, Ids: ids})
}

func (r *Repo) GetHostIP(ctx context.Context, hostID, ipID int32) (*inventory.HostIP, error) {
	ip, err := r.q.GetHostIPForHost(ctx, sqlc.GetHostIPForHostParams{ID: ipID, HostID: hostID})
	if err != nil {
		return nil, mapErr(err)
	}
	out := mapHostIP(ip)
	return &out, nil
}

func (r *Repo) LoadTrees(ctx context.Context, hosts []inventory.Host) ([]inventory.HostAggregate, error) {
	if len(hosts) == 0 {
		return []inventory.HostAggregate{}, nil
	}
	hostIDs := make([]int32, 0, len(hosts))
	for _, h := range hosts {
		hostIDs = append(hostIDs, h.ID)
	}

	ipRows, err := r.q.ListHostIPsForHosts(ctx, hostIDs)
	if err != nil {
		return nil, err
	}
	ipByHost := map[int32][]inventory.HostIP{}
	ipIDs := make([]int32, 0, len(ipRows))
	for _, row := range ipRows {
		ip := mapHostIP(row)
		ipByHost[ip.HostID] = append(ipByHost[ip.HostID], ip)
		ipIDs = append(ipIDs, ip.ID)
	}

	portByIP := map[int32][]inventory.Port{}
	portIDs := []int32{}
	if len(ipIDs) > 0 {
		portRows, err := r.q.ListPortsForIPs(ctx, ipIDs)
		if err != nil {
			return nil, err
		}
		for _, row := range portRows {
			p := mapPort(row)
			portByIP[p.IPAddressID] = append(portByIP[p.IPAddressID], p)
			portIDs = append(portIDs, p.ID)
		}
	}

	svcByPort := map[int32][]inventory.PortService{}
	if len(portIDs) > 0 {
		svcRows, err := r.q.ListServicesForPorts(ctx, portIDs)
		if err != nil {
			return nil, err
		}
		for _, row := range svcRows {
			s := mapService(row)
			svcByPort[s.PortID] = append(svcByPort[s.PortID], s)
		}
	}

	epRows, err := r.q.ListEndpointsForHosts(ctx, hostIDs)
	if err != nil {
		return nil, err
	}
	epByHost := map[int32][]inventory.Endpoint{}
	for _, row := range epRows {
		e := mapEndpoint(row)
		epByHost[e.HostID] = append(epByHost[e.HostID], e)
	}

	out := make([]inventory.HostAggregate, 0, len(hosts))
	for _, h := range hosts {
		ipAggs := make([]inventory.IPAggregate, 0, len(ipByHost[h.ID]))
		for _, ip := range ipByHost[h.ID] {
			portAggs := make([]inventory.PortAggregate, 0, len(portByIP[ip.ID]))
			for _, port := range portByIP[ip.ID] {
				svcs := svcByPort[port.ID]
				if svcs == nil {
					svcs = []inventory.PortService{}
				}
				portAggs = append(portAggs, inventory.PortAggregate{Port: port, Services: svcs})
			}
			ipAggs = append(ipAggs, inventory.IPAggregate{IP: ip, Ports: portAggs})
		}
		eps := epByHost[h.ID]
		if eps == nil {
			eps = []inventory.Endpoint{}
		}
		out = append(out, inventory.HostAggregate{Host: h, IPs: ipAggs, Endpoints: eps})
	}
	return out, nil
}

// ─────────────────────────── ports ───────────────────────────

func (r *Repo) ListPortsForHost(ctx context.Context, hostID int32) ([]inventory.Port, error) {
	rows, err := r.q.ListPortsForHost(ctx, hostID)
	if err != nil {
		return nil, err
	}
	out := make([]inventory.Port, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapPort(row))
	}
	return out, nil
}

func (r *Repo) GetPort(ctx context.Context, hostID, portID int32) (*inventory.Port, error) {
	p, err := r.q.GetPort(ctx, sqlc.GetPortParams{ID: portID, HostID: hostID})
	if err != nil {
		return nil, mapErr(err)
	}
	port := mapPort(p)
	return &port, nil
}

func (r *Repo) FindPortDup(ctx context.Context, ipAddressID, portNumber int32, protocol string, excludeID int32) (bool, error) {
	_, err := r.q.FindPortDup(ctx, sqlc.FindPortDupParams{
		IpAddressID: ipAddressID, PortNumber: portNumber, Protocol: sqlc.PortProtocol(protocol), ExcludeID: excludeID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *Repo) InsertPort(ctx context.Context, np inventory.NewPort) (*inventory.Port, error) {
	p, err := r.q.InsertPort(ctx, sqlc.InsertPortParams{
		HostID: np.HostID, IpAddressID: np.IPAddressID, PortNumber: np.PortNumber,
		Protocol: sqlc.PortProtocol(np.Protocol), State: sqlc.PortState(np.State), HttpStatus: pgconv.Int4(np.HTTPStatus),
	})
	if err != nil {
		return nil, err
	}
	port := mapPort(p)
	return &port, nil
}

func (r *Repo) UpdatePort(ctx context.Context, p inventory.UpdatePortParams) (*inventory.Port, error) {
	row, err := r.q.UpdatePort(ctx, sqlc.UpdatePortParams{
		ID: p.ID, IpAddressID: p.IPAddressID, PortNumber: p.PortNumber,
		Protocol: sqlc.PortProtocol(p.Protocol), State: sqlc.PortState(p.State), HttpStatus: pgconv.Int4(p.HTTPStatus),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	port := mapPort(row)
	return &port, nil
}

func (r *Repo) DeletePort(ctx context.Context, portID int32) error {
	return r.q.DeletePort(ctx, portID)
}

// ─────────────────────────── services ───────────────────────────

func (r *Repo) ListServicesForPort(ctx context.Context, portID int32) ([]inventory.PortService, error) {
	rows, err := r.q.ListServicesForPort(ctx, portID)
	if err != nil {
		return nil, err
	}
	out := make([]inventory.PortService, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapService(row))
	}
	return out, nil
}

func (r *Repo) GetServiceForPort(ctx context.Context, portID, serviceID int32) (*inventory.PortService, error) {
	s, err := r.q.GetServiceForPort(ctx, sqlc.GetServiceForPortParams{ID: serviceID, PortID: portID})
	if err != nil {
		return nil, mapErr(err)
	}
	svc := mapService(s)
	return &svc, nil
}

func (r *Repo) InsertService(ctx context.Context, portID int32, name string, version, banner *string) (*inventory.PortService, error) {
	s, err := r.q.InsertService(ctx, sqlc.InsertServiceParams{
		PortID: portID, Name: name, Version: pgconv.TextPtr(version), Banner: pgconv.TextPtr(banner),
	})
	if err != nil {
		return nil, err
	}
	svc := mapService(s)
	return &svc, nil
}

func (r *Repo) UpdateService(ctx context.Context, id int32, name string, version, banner *string) (*inventory.PortService, error) {
	s, err := r.q.UpdateService(ctx, sqlc.UpdateServiceParams{
		ID: id, Name: name, Version: pgconv.TextPtr(version), Banner: pgconv.TextPtr(banner),
	})
	if err != nil {
		return nil, mapErr(err)
	}
	svc := mapService(s)
	return &svc, nil
}

func (r *Repo) DeleteService(ctx context.Context, id int32) error {
	return r.q.DeleteService(ctx, id)
}

// ─────────────────────────── endpoints ───────────────────────────

func (r *Repo) ListEndpointsForHost(ctx context.Context, hostID int32) ([]inventory.Endpoint, error) {
	rows, err := r.q.ListEndpointsForHost(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return mapEndpoints(rows), nil
}

func (r *Repo) ListEndpointsForHostOrdered(ctx context.Context, hostID int32) ([]inventory.Endpoint, error) {
	rows, err := r.q.ListEndpointsForHostOrdered(ctx, hostID)
	if err != nil {
		return nil, err
	}
	return mapEndpoints(rows), nil
}

func mapEndpoints(rows []sqlc.Endpoint) []inventory.Endpoint {
	out := make([]inventory.Endpoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, mapEndpoint(row))
	}
	return out
}

func (r *Repo) GetEndpointForHost(ctx context.Context, hostID, endpointID int32) (*inventory.Endpoint, error) {
	e, err := r.q.GetEndpointForHost(ctx, sqlc.GetEndpointForHostParams{ID: endpointID, HostID: hostID})
	if err != nil {
		return nil, mapErr(err)
	}
	ep := mapEndpoint(e)
	return &ep, nil
}

func (r *Repo) FindEndpointDup(ctx context.Context, hostID int32, path string, method *string, excludeID int32) (*inventory.Endpoint, error) {
	e, err := r.q.FindEndpointByPathMethod(ctx, sqlc.FindEndpointByPathMethodParams{
		HostID: hostID, Path: path, Method: nullMethod(method), ExcludeID: excludeID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	ep := mapEndpoint(e)
	return &ep, nil
}

func (r *Repo) InsertEndpoint(ctx context.Context, ne inventory.NewEndpoint) (*inventory.Endpoint, error) {
	e, err := r.q.InsertEndpoint(ctx, sqlc.InsertEndpointParams{
		HostID:             ne.HostID,
		Path:               ne.Path,
		Method:             nullMethod(ne.Method),
		Description:        pgconv.TextPtr(ne.Description),
		QueryParams:        ne.QueryParams,
		RequestBody:        pgconv.TextPtr(ne.RequestBody),
		RequestContentType: pgconv.TextPtr(ne.RequestContentType),
		RequestHeaders:     ne.RequestHeaders,
	})
	if err != nil {
		return nil, err
	}
	ep := mapEndpoint(e)
	return &ep, nil
}

func (r *Repo) UpdateEndpoint(ctx context.Context, p inventory.UpdateEndpointParams) (*inventory.Endpoint, error) {
	e, err := r.q.UpdateEndpoint(ctx, sqlc.UpdateEndpointParams{
		ID:                 p.ID,
		Path:               p.Path,
		Method:             nullMethod(p.Method),
		Description:        pgconv.TextPtr(p.Description),
		QueryParams:        p.QueryParams,
		RequestBody:        pgconv.TextPtr(p.RequestBody),
		RequestContentType: pgconv.TextPtr(p.RequestContentType),
		RequestHeaders:     p.RequestHeaders,
	})
	if err != nil {
		return nil, mapErr(err)
	}
	ep := mapEndpoint(e)
	return &ep, nil
}

func (r *Repo) DeleteEndpoint(ctx context.Context, id int32) error {
	return r.q.DeleteEndpoint(ctx, id)
}

func (r *Repo) BulkDeleteEndpoints(ctx context.Context, projectID int32, ids []int32) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	return r.q.BulkDeleteEndpoints(ctx, sqlc.BulkDeleteEndpointsParams{ProjectID: projectID, Ids: ids})
}

// ─────────────────────────── audit ───────────────────────────

func (r *Repo) InsertAudit(ctx context.Context, e inventory.AuditEntry) error {
	return r.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		UserID:     pgconv.Int4(e.UserID),
		Action:     e.Action,
		EntityType: pgconv.Text(e.EntityType),
		EntityID:   pgconv.Int4(e.EntityID),
		Details:    e.Details,
		IpAddress:  pgconv.Text(e.IPAddress),
	})
}

// ─────────────────────────── enum/bool helpers ───────────────────────────

func nullStatus(status string) sqlc.NullHostStatus {
	if status == "" {
		return sqlc.NullHostStatus{}
	}
	return sqlc.NullHostStatus{HostStatus: sqlc.HostStatus(status), Valid: true}
}

func nullMethod(m *string) sqlc.NullHttpMethod {
	if m == nil {
		return sqlc.NullHttpMethod{}
	}
	return sqlc.NullHttpMethod{HttpMethod: sqlc.HttpMethod(*m), Valid: true}
}

func methodPtr(m sqlc.NullHttpMethod) *string {
	if !m.Valid {
		return nil
	}
	s := string(m.HttpMethod)
	return &s
}

func boolValPtr(b pgtype.Bool) *bool {
	if !b.Valid {
		return nil
	}
	v := b.Bool
	return &v
}

// cfBoolForNew — tri-state is_cloudflare для новой строки: true если адрес в
// CIDR Cloudflare, иначе NULL (ручное добавление не пробивает).
func cfBoolForNew(ip string) pgtype.Bool {
	if inventory.IsCloudflareIP(ip) {
		return pgtype.Bool{Bool: true, Valid: true}
	}
	return pgtype.Bool{}
}
