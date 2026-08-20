package inventory

import (
	"context"
	"errors"
)

// ErrNoRows — репозиторий не нашёл строку. Use-case решает трактовку.
var ErrNoRows = errors.New("no rows")

// ErrNoImport — импорт не создал/не обновил ни одного эндпоинта (→ 422).
var ErrNoImport = errors.New("no import")

// Store — порт хранилища контекста inventory (реализуется inventoryrepo поверх
// sqlc + pgxpool). Компаундные операции (создание/обновление хоста с заменой IP,
// импорт) атомарны внутри адаптера (транзакция).
type Store interface {
	// hosts
	ListHostsPage(ctx context.Context, p HostListParams) ([]Host, int64, error)
	GetHost(ctx context.Context, projectID, hostID int32) (*Host, error)
	CreateHost(ctx context.Context, nh NewHost, entries []IPEntry) (int32, error)
	UpdateHost(ctx context.Context, p HostUpdateParams) error
	DeleteHost(ctx context.Context, projectID, hostID int32) error
	LoadTrees(ctx context.Context, hosts []Host) ([]HostAggregate, error)
	GetHostIP(ctx context.Context, hostID, ipID int32) (*HostIP, error)
	ListProjectHosts(ctx context.Context, projectID int32) ([]Host, error)

	// ports
	ListPortsForHost(ctx context.Context, hostID int32) ([]Port, error)
	GetPort(ctx context.Context, hostID, portID int32) (*Port, error)
	FindPortDup(ctx context.Context, ipAddressID, portNumber int32, protocol string, excludeID int32) (bool, error)
	InsertPort(ctx context.Context, np NewPort) (*Port, error)
	UpdatePort(ctx context.Context, p UpdatePortParams) (*Port, error)
	DeletePort(ctx context.Context, portID int32) error

	// services
	ListServicesForPort(ctx context.Context, portID int32) ([]PortService, error)
	GetServiceForPort(ctx context.Context, portID, serviceID int32) (*PortService, error)
	InsertService(ctx context.Context, portID int32, name string, version, banner *string) (*PortService, error)
	UpdateService(ctx context.Context, id int32, name string, version, banner *string) (*PortService, error)
	DeleteService(ctx context.Context, id int32) error

	// endpoints
	ListEndpointsForHost(ctx context.Context, hostID int32) ([]Endpoint, error)
	ListEndpointsForHostOrdered(ctx context.Context, hostID int32) ([]Endpoint, error)
	GetEndpointForHost(ctx context.Context, hostID, endpointID int32) (*Endpoint, error)
	FindEndpointDup(ctx context.Context, hostID int32, path string, method *string, excludeID int32) (*Endpoint, error)
	InsertEndpoint(ctx context.Context, ne NewEndpoint) (*Endpoint, error)
	UpdateEndpoint(ctx context.Context, p UpdateEndpointParams) (*Endpoint, error)
	DeleteEndpoint(ctx context.Context, id int32) error

	// import (атомарные)
	UpsertOpenAPIEndpoints(ctx context.Context, hostID int32, eps []EndpointImport) (created, skipped int, err error)
	ImportPCF(ctx context.Context, projectID int32, hosts []PcfHost) (ImportResult, error)

	// audit
	InsertAudit(ctx context.Context, e AuditEntry) error
}
