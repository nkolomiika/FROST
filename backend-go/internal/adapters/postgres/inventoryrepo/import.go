package inventoryrepo

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/inventory"
	"github.com/nkolomiika/frost/internal/apperr"
)

// UpsertOpenAPIEndpoints — атомарный upsert эндпоинтов из OpenAPI (fill-empty
// merge для существующих). created+skipped==0 → ErrNoImport (rollback).
func (r *Repo) UpsertOpenAPIEndpoints(ctx context.Context, hostID int32, eps []inventory.EndpointImport) (int, int, error) {
	created, skipped := 0, 0
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		for _, ep := range eps {
			existing, err := q.FindEndpointByPathMethod(ctx, sqlc.FindEndpointByPathMethodParams{
				HostID: hostID, Path: ep.Path, Method: nullMethod(ep.Method), ExcludeID: 0,
			})
			if errors.Is(err, pgx.ErrNoRows) {
				if _, err := q.InsertEndpoint(ctx, insertEndpointParams(hostID, ep)); err != nil {
					return err
				}
				created++
				continue
			}
			if err != nil {
				return err
			}
			if _, err := q.UpdateEndpoint(ctx, mergeImportEndpoint(existing, ep)); err != nil {
				return err
			}
			skipped++
		}
		if created+skipped == 0 {
			return inventory.ErrNoImport
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, inventory.ErrNoImport) {
			return 0, 0, inventory.ErrNoImport
		}
		return 0, 0, err
	}
	return created, skipped, nil
}

// ImportPCF — атомарный импорт активов PCF (hosts/ports/services/endpoints upsert).
func (r *Repo) ImportPCF(ctx context.Context, projectID int32, hosts []inventory.PcfHost) (inventory.ImportResult, error) {
	result := inventory.ImportResult{Errors: []string{}}
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		for _, hd := range hosts {
			host, err := findMatchingHost(ctx, q, projectID, hd)
			if err != nil {
				return err
			}
			var hostRow sqlc.Host
			if host == nil {
				hostRow, err = q.InsertHost(ctx, sqlc.InsertHostParams{
					ProjectID: projectID,
					IpAddress: pgconv.TextPtr(hd.IPAddress),
					Hostname:  pgconv.TextPtr(hd.Hostname),
					Status:    sqlc.HostStatus(hd.Status),
					OsType:    sqlc.HostOsType("UNKNOWN"),
					Notes:     pgconv.TextPtr(hd.Notes),
					Origin:    "host",
				})
				if err != nil {
					return err
				}
				result.HostsCreated++
			} else {
				hostRow, err = q.UpdateHost(ctx, mergeHostFields(*host, hd))
				if err != nil {
					return err
				}
			}

			ips, err := q.ListHostIPs(ctx, hostRow.ID)
			if err != nil {
				return err
			}
			var primary *sqlc.HostIpAddress
			for i := range ips {
				if ips[i].IsPrimary {
					primary = &ips[i]
					break
				}
			}
			if primary == nil && len(ips) > 0 {
				primary = &ips[0]
			}
			if primary == nil {
				return apperr.Validation("Невозможно импортировать порты: у хоста нет IP-адресов")
			}

			for _, pd := range hd.Ports {
				var portRow sqlc.Port
				existingPort, err := q.FindPortDup(ctx, sqlc.FindPortDupParams{
					IpAddressID: primary.ID, PortNumber: pd.PortNumber, Protocol: sqlc.PortProtocol(pd.Protocol), ExcludeID: 0,
				})
				if errors.Is(err, pgx.ErrNoRows) {
					portRow, err = q.InsertPort(ctx, sqlc.InsertPortParams{
						HostID: hostRow.ID, IpAddressID: primary.ID, PortNumber: pd.PortNumber,
						Protocol: sqlc.PortProtocol(pd.Protocol), State: sqlc.PortState(pd.State), HttpStatus: pgtype.Int4{},
					})
					if err != nil {
						return err
					}
					result.PortsCreated++
				} else if err != nil {
					return err
				} else {
					portRow = existingPort
				}

				for _, sd := range pd.Services {
					existingSvc, err := q.FindServiceByName(ctx, sqlc.FindServiceByNameParams{PortID: portRow.ID, Name: sd.Name})
					if errors.Is(err, pgx.ErrNoRows) {
						if _, err := q.InsertService(ctx, sqlc.InsertServiceParams{
							PortID: portRow.ID, Name: sd.Name, Version: pgconv.TextPtr(sd.Version), Banner: pgconv.TextPtr(sd.Banner),
						}); err != nil {
							return err
						}
						result.ServicesCreated++
					} else if err != nil {
						return err
					} else if params, changed := mergeServiceFields(existingSvc, sd); changed {
						if _, err := q.UpdateService(ctx, params); err != nil {
							return err
						}
					}
				}
			}

			for _, ed := range hd.Endpoints {
				existing, err := q.FindEndpointByPathMethod(ctx, sqlc.FindEndpointByPathMethodParams{
					HostID: hostRow.ID, Path: ed.Path, Method: nullMethod(ed.Method), ExcludeID: 0,
				})
				if errors.Is(err, pgx.ErrNoRows) {
					if _, err := q.InsertEndpoint(ctx, insertEndpointParams(hostRow.ID, ed)); err != nil {
						return err
					}
					result.EndpointsCreated++
				} else if err != nil {
					return err
				} else if _, err := q.UpdateEndpoint(ctx, mergeImportEndpoint(existing, ed)); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return inventory.ImportResult{}, err
	}
	return result, nil
}

// findMatchingHost — порт _find_matching_host (несколько совпадений → 422).
func findMatchingHost(ctx context.Context, q *sqlc.Queries, projectID int32, hd inventory.PcfHost) (*sqlc.Host, error) {
	ipClause := hd.IPAddress != nil && *hd.IPAddress != ""
	hnClause := hd.Hostname != nil && *hd.Hostname != ""
	if !ipClause && !hnClause {
		return nil, nil
	}
	rows, err := q.ListHosts(ctx, sqlc.ListHostsParams{ProjectID: projectID, Offset: 0, Lim: 1_000_000})
	if err != nil {
		return nil, err
	}
	matches := []sqlc.Host{}
	for _, h := range rows {
		matched := false
		if ipClause && h.IpAddress.Valid && h.IpAddress.String == *hd.IPAddress {
			matched = true
		}
		if hnClause && h.Hostname.Valid && h.Hostname.String == *hd.Hostname {
			matched = true
		}
		if matched {
			matches = append(matches, h)
		}
	}
	if len(matches) == 0 {
		return nil, nil
	}
	for i := range matches {
		if textEq(matches[i].IpAddress, hd.IPAddress) && textEq(matches[i].Hostname, hd.Hostname) {
			return &matches[i], nil
		}
	}
	if len(matches) == 1 {
		return &matches[0], nil
	}
	return nil, apperr.Validation(fmt.Sprintf(
		"Найдено несколько host для ip/hostname (%s / %s)", dashIfEmpty(hd.IPAddress), dashIfEmpty(hd.Hostname)))
}

func mergeHostFields(existing sqlc.Host, hd inventory.PcfHost) sqlc.UpdateHostParams {
	ip := existing.IpAddress
	if isEmptyText(existing.IpAddress) && hd.IPAddress != nil && *hd.IPAddress != "" {
		ip = pgconv.TextPtr(hd.IPAddress)
	}
	hn := existing.Hostname
	if isEmptyText(existing.Hostname) && hd.Hostname != nil && *hd.Hostname != "" {
		hn = pgconv.TextPtr(hd.Hostname)
	}
	status := existing.Status
	if string(existing.Status) == "UNKNOWN" && hd.Status != "UNKNOWN" {
		status = sqlc.HostStatus(hd.Status)
	}
	notes := existing.Notes
	if isEmptyText(existing.Notes) && hd.Notes != nil && *hd.Notes != "" {
		notes = pgconv.TextPtr(hd.Notes)
	}
	return sqlc.UpdateHostParams{
		ID: existing.ID, IpAddress: ip, Hostname: hn, Status: status, OsType: existing.OsType, Notes: notes,
	}
}

func mergeServiceFields(existing sqlc.Service, sd inventory.PcfService) (sqlc.UpdateServiceParams, bool) {
	version := existing.Version
	banner := existing.Banner
	changed := false
	if isEmptyText(existing.Version) && sd.Version != nil && *sd.Version != "" {
		version = pgconv.TextPtr(sd.Version)
		changed = true
	}
	if isEmptyText(existing.Banner) && sd.Banner != nil && *sd.Banner != "" {
		banner = pgconv.TextPtr(sd.Banner)
		changed = true
	}
	return sqlc.UpdateServiceParams{ID: existing.ID, Name: existing.Name, Version: version, Banner: banner}, changed
}

func mergeImportEndpoint(existing sqlc.Endpoint, ep inventory.EndpointImport) sqlc.UpdateEndpointParams {
	p := sqlc.UpdateEndpointParams{
		ID:                 existing.ID,
		Path:               existing.Path,
		Method:             existing.Method,
		Description:        existing.Description,
		QueryParams:        existing.QueryParams,
		RequestBody:        existing.RequestBody,
		RequestContentType: existing.RequestContentType,
		RequestHeaders:     existing.RequestHeaders,
	}
	if isEmptyText(existing.Description) && strPtrTruthy(ep.Description) {
		p.Description = pgconv.TextPtr(ep.Description)
	}
	if isEmptyJSONB(existing.QueryParams) && !isEmptyJSONB(ep.QueryParams) {
		p.QueryParams = ep.QueryParams
	}
	if isEmptyText(existing.RequestBody) && strPtrTruthy(ep.RequestBody) {
		p.RequestBody = pgconv.TextPtr(ep.RequestBody)
	}
	if isEmptyText(existing.RequestContentType) && strPtrTruthy(ep.RequestContentType) {
		p.RequestContentType = pgconv.TextPtr(ep.RequestContentType)
	}
	if isEmptyJSONB(existing.RequestHeaders) && !isEmptyJSONB(ep.RequestHeaders) {
		p.RequestHeaders = ep.RequestHeaders
	}
	return p
}

func insertEndpointParams(hostID int32, ep inventory.EndpointImport) sqlc.InsertEndpointParams {
	return sqlc.InsertEndpointParams{
		HostID:             hostID,
		Path:               ep.Path,
		Method:             nullMethod(ep.Method),
		Description:        pgconv.TextPtr(ep.Description),
		QueryParams:        ep.QueryParams,
		RequestBody:        pgconv.TextPtr(ep.RequestBody),
		RequestContentType: pgconv.TextPtr(ep.RequestContentType),
		RequestHeaders:     ep.RequestHeaders,
	}
}

// ─────────────────────────── helpers ───────────────────────────

func isEmptyText(t pgtype.Text) bool { return !t.Valid || t.String == "" }

func isEmptyJSONB(raw []byte) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "[]" || s == "{}" || s == `""`
}

func strPtrTruthy(s *string) bool { return s != nil && *s != "" }

func textEq(t pgtype.Text, p *string) bool {
	hostNone := !t.Valid
	dataNone := p == nil
	if hostNone && dataNone {
		return true
	}
	if hostNone != dataNone {
		return false
	}
	return t.String == *p
}

func dashIfEmpty(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}
