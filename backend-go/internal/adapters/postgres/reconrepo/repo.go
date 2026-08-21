// Package reconrepo — реализация порта recon.Store поверх sqlc + pgxpool.
// Persist-методы компаундны (find-or-create хоста, ensure_ips со стики-CF-логикой,
// upsert портов, замена сервисов) и выполняются в транзакции на элемент — зеркало
// похостного commit Python-фермы.
package reconrepo

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/inventory"
	"github.com/nkolomiika/frost/internal/app/recon"
)

// Repo реализует recon.Store.
type Repo struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// New создаёт репозиторий поверх пула соединений.
func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool, q: sqlc.New(pool)} }

var _ recon.Store = (*Repo)(nil)

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

func nullBool(p *bool) pgtype.Bool {
	if p == nil {
		return pgtype.Bool{}
	}
	return pgtype.Bool{Bool: *p, Valid: true}
}

func boolValPtr(b pgtype.Bool) *bool {
	if !b.Valid {
		return nil
	}
	v := b.Bool
	return &v
}

func textList(rows []pgtype.Text) []string {
	out := make([]string, 0, len(rows))
	for _, t := range rows {
		if t.Valid && t.String != "" {
			out = append(out, t.String)
		}
	}
	return out
}

// ─────────────────────────── очередь задач ───────────────────────────

func mapJobView(j sqlc.HostFarmJob) recon.JobView {
	return recon.JobView{
		ID:           j.ID,
		ProjectID:    j.ProjectID,
		Kind:         j.Kind,
		Status:       j.Status,
		TargetsTotal: pgconv.Int4Val(j.TargetsTotal),
		Result:       j.Result,
		Progress:     j.Progress,
		Error:        pgconv.TextValPtr(j.Error),
		CreatedAt:    pgconv.TsVal(j.CreatedAt),
	}
}

func (r *Repo) InsertJob(ctx context.Context, j recon.NewJob) (recon.JobView, error) {
	var skipped []byte
	if j.SkippedTargets != nil {
		skipped, _ = json.Marshal(j.SkippedTargets)
	}
	finished := pgtype.Timestamptz{}
	if j.Finished {
		finished = pgconv.Ts(time.Now())
	}
	row, err := r.q.InsertHostFarmJob(ctx, sqlc.InsertHostFarmJobParams{
		ProjectID:      j.ProjectID,
		CreatedBy:      j.CreatedBy,
		Kind:           j.Kind,
		Status:         j.Status,
		TargetsTotal:   pgconv.Int4(j.TargetsTotal),
		Raw:            pgconv.Text(j.Raw),
		SkippedTargets: skipped,
		Result:         j.Result,
		Progress:       j.Progress,
		FinishedAt:     finished,
	})
	if err != nil {
		return recon.JobView{}, err
	}
	return mapJobView(row), nil
}

func (r *Repo) GetJobForProject(ctx context.Context, projectID, jobID int32, kind string) (recon.JobView, error) {
	row, err := r.q.GetHostFarmJobForProject(ctx, sqlc.GetHostFarmJobForProjectParams{ID: jobID, ProjectID: projectID, Kind: kind})
	if errors.Is(err, pgx.ErrNoRows) {
		return recon.JobView{}, recon.ErrNoRows
	}
	if err != nil {
		return recon.JobView{}, err
	}
	return mapJobView(row), nil
}

func (r *Repo) ClaimJobRunning(ctx context.Context, id int32) (*recon.JobClaim, error) {
	row, err := r.q.ClaimReconJobRunning(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil // уже running/done — не берём
	}
	if err != nil {
		return nil, err
	}
	var skipped []string
	if len(row.SkippedTargets) > 0 {
		_ = json.Unmarshal(row.SkippedTargets, &skipped)
	}
	return &recon.JobClaim{
		ID:             row.ID,
		ProjectID:      row.ProjectID,
		CreatedBy:      row.CreatedBy,
		Kind:           row.Kind,
		Raw:            pgconv.TextVal(row.Raw),
		SkippedTargets: skipped,
		Attempts:       row.Attempts,
	}, nil
}

func (r *Repo) UpdateJobProgress(ctx context.Context, id int32, progress []byte) error {
	return r.q.SetJobProgress(ctx, sqlc.SetJobProgressParams{ID: id, Progress: progress})
}

func (r *Repo) MarkJobDone(ctx context.Context, id int32, result []byte) error {
	return r.q.SetJobDone(ctx, sqlc.SetJobDoneParams{ID: id, Result: result})
}

func (r *Repo) MarkJobFailed(ctx context.Context, id int32, lastErr string, terminalErr *string) error {
	return r.q.SetJobFailed(ctx, sqlc.SetJobFailedParams{
		ID:        id,
		LastError: pgconv.Text(lastErr),
		Error:     pgconv.TextPtr(terminalErr),
	})
}

func (r *Repo) SelectPendingJobIDs(ctx context.Context, maxAttempts, limit int32) ([]int32, error) {
	return r.q.SelectPendingReconJobs(ctx, sqlc.SelectPendingReconJobsParams{MaxAttempts: maxAttempts, Lim: limit})
}

func (r *Repo) ReclaimStale(ctx context.Context, staleSeconds, maxAttempts int32) (int64, error) {
	return r.q.ReclaimStaleReconJobs(ctx, sqlc.ReclaimStaleReconJobsParams{StaleSeconds: staleSeconds, MaxAttempts: maxAttempts})
}

// ─────────────────────────── create_job helpers ───────────────────────────

func (r *Repo) ExistingHostnames(ctx context.Context, projectID int32, names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	rows, err := r.q.SelectExistingHostnames(ctx, sqlc.SelectExistingHostnamesParams{ProjectID: projectID, Names: names})
	if err != nil {
		return nil, err
	}
	return textList(rows), nil
}

func (r *Repo) ExistingHostIPLiterals(ctx context.Context, projectID int32, addrs []string) ([]string, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	rows, err := r.q.SelectExistingHostIPLiterals(ctx, sqlc.SelectExistingHostIPLiteralsParams{ProjectID: projectID, Addrs: addrs})
	if err != nil {
		return nil, err
	}
	return textList(rows), nil
}

func (r *Repo) ExistingOriginIPs(ctx context.Context, projectID int32, addrs []string) ([]string, error) {
	if len(addrs) == 0 {
		return nil, nil
	}
	return r.q.SelectExistingOriginIPAddresses(ctx, sqlc.SelectExistingOriginIPAddressesParams{ProjectID: projectID, Addrs: addrs})
}

func (r *Repo) EnsureHostSkeletons(ctx context.Context, projectID int32, hosts []recon.SkeletonHost) error {
	if len(hosts) == 0 {
		return nil
	}
	return r.tx(ctx, func(q *sqlc.Queries) error {
		for _, h := range hosts {
			if _, err := q.InsertHost(ctx, sqlc.InsertHostParams{
				ProjectID: projectID,
				IpAddress: pgconv.TextPtr(h.IPAddress),
				Hostname:  pgconv.TextPtr(h.Hostname),
				Status:    sqlc.HostStatusUNKNOWN,
				OsType:    sqlc.HostOsType("UNKNOWN"),
				Origin:    "host",
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Repo) DeleteHiddenIPs(ctx context.Context, projectID int32, addrs []string) error {
	if len(addrs) == 0 {
		return nil
	}
	return r.q.DeleteHiddenIPs(ctx, sqlc.DeleteHiddenIPsParams{ProjectID: projectID, Addrs: addrs})
}

// ─────────────────────────── общие persist-хелперы ───────────────────────────

// ensureIPs заводит ВСЕ адреса хоста; первый становится primary. Порт _ensure_ips
// со стики-логикой is_cloudflare (True/False/None по силе сигнала).
func (r *Repo) ensureIPs(ctx context.Context, q *sqlc.Queries, hostID int32, existing []sqlc.HostIpAddress, ips []string, cfHint, cfResponded bool) (primaryID int32, primaryOK bool, primaryCF *bool, newPrimaryIP *string, err error) {
	cur := append([]sqlc.HostIpAddress(nil), existing...)
	anyPrimary := false
	for _, row := range cur {
		if row.IsPrimary {
			anyPrimary = true
		}
	}
	for idx, ip := range ips {
		cf := inventory.IsCloudflareIP(ip) || cfHint
		var cfState *bool
		if cf {
			t := true
			cfState = &t
		} else if cfResponded {
			f := false
			cfState = &f
		}

		var found *sqlc.HostIpAddress
		for i := range cur {
			if cur[i].IpAddress == ip {
				found = &cur[i]
				break
			}
		}
		var rowCF *bool
		if found == nil {
			isPrimary := idx == 0 && !anyPrimary
			inserted, ierr := q.InsertHostIP(ctx, sqlc.InsertHostIPParams{
				HostID:       hostID,
				IpAddress:    ip,
				IsPrimary:    isPrimary,
				IsCloudflare: nullBool(cfState),
			})
			if ierr != nil {
				return 0, false, nil, nil, ierr
			}
			cur = append(cur, inserted)
			found = &cur[len(cur)-1]
			rowCF = cfState
			if isPrimary {
				if err := q.SetHostPrimaryIP(ctx, sqlc.SetHostPrimaryIPParams{ID: hostID, IpAddress: pgconv.Text(ip)}); err != nil {
					return 0, false, nil, nil, err
				}
				np := ip
				newPrimaryIP = &np
				anyPrimary = true
			}
		} else if cf {
			if err := q.SetHostIPCloudflare(ctx, sqlc.SetHostIPCloudflareParams{ID: found.ID, IsCloudflare: pgtype.Bool{Bool: true, Valid: true}}); err != nil {
				return 0, false, nil, nil, err
			}
			t := true
			rowCF = &t
		} else if cfResponded {
			if err := q.SetHostIPCloudflare(ctx, sqlc.SetHostIPCloudflareParams{ID: found.ID, IsCloudflare: pgtype.Bool{Bool: false, Valid: true}}); err != nil {
				return 0, false, nil, nil, err
			}
			f := false
			rowCF = &f
		} else {
			rowCF = boolValPtr(found.IsCloudflare)
		}
		if idx == 0 {
			primaryID = found.ID
			primaryOK = true
			primaryCF = rowCF
		}
	}
	return primaryID, primaryOK, primaryCF, newPrimaryIP, nil
}

// upsertPort — веб-порт (ферма хостов/IP): пишем state + http_status + сервисы.
func (r *Repo) upsertPort(ctx context.Context, q *sqlc.Queries, hostID, ipAddrID int32, pw recon.PortWrite) (bool, error) {
	existing, err := q.GetPortByIPNumberProto(ctx, sqlc.GetPortByIPNumberProtoParams{
		IpAddressID: ipAddrID, PortNumber: pw.PortNumber, Protocol: sqlc.PortProtocolTCP,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if err == nil {
		if serr := q.SetPortStateHTTP(ctx, sqlc.SetPortStateHTTPParams{
			ID: existing.ID, State: sqlc.PortState(pw.State), HttpStatus: pgconv.Int4(pw.HTTPStatus),
		}); serr != nil {
			return false, serr
		}
		return false, r.replaceServices(ctx, q, existing.ID, pw)
	}
	port, ierr := q.InsertPort(ctx, sqlc.InsertPortParams{
		HostID: hostID, IpAddressID: ipAddrID, PortNumber: pw.PortNumber,
		Protocol: sqlc.PortProtocolTCP, State: sqlc.PortState(pw.State), HttpStatus: pgconv.Int4(pw.HTTPStatus),
	})
	if ierr != nil {
		return false, ierr
	}
	return true, r.replaceServices(ctx, q, port.ID, pw)
}

// replaceServices заменяет технологии порта (порт _replace_services). HasTechs=false
// (детект не запускался) — сервисы не трогаем.
func (r *Repo) replaceServices(ctx context.Context, q *sqlc.Queries, portID int32, pw recon.PortWrite) error {
	if !pw.HasTechs {
		return nil
	}
	if err := q.DeleteServicesForPort(ctx, portID); err != nil {
		return err
	}
	for _, tech := range pw.Techs {
		name := tech.Name
		if len(name) > 100 {
			name = name[:100]
		}
		if _, err := q.InsertService(ctx, sqlc.InsertServiceParams{
			PortID: portID, Name: name, Version: pgconv.TextPtr(tech.Version), Banner: pgtype.Text{},
		}); err != nil {
			return err
		}
	}
	return nil
}

func finalHostFields(h sqlc.Host, newPrimaryIP *string) (*string, *string) {
	hostname := pgconv.TextValPtr(h.Hostname)
	ipAddr := pgconv.TextValPtr(h.IpAddress)
	if newPrimaryIP != nil {
		ipAddr = newPrimaryIP
	}
	return hostname, ipAddr
}

// findOrCreateHost — порт _find_or_create_host (origin='host'). Домен ищется по
// hostname, IP-литерал — по ip_address; найденному ставится status.
func (r *Repo) findOrCreateHost(ctx context.Context, q *sqlc.Queries, in recon.HostPersistInput) (sqlc.Host, bool, error) {
	var ipValue pgtype.Text
	if in.HasIP && len(in.IPs) > 0 {
		ipValue = pgconv.Text(in.IPs[0])
	}
	var host sqlc.Host
	var err error
	if in.IsIP {
		host, err = q.GetHostByIPLiteral(ctx, sqlc.GetHostByIPLiteralParams{ProjectID: in.ProjectID, IpAddress: pgconv.Text(in.TargetKey)})
	} else {
		host, err = q.GetHostByHostname(ctx, sqlc.GetHostByHostnameParams{ProjectID: in.ProjectID, Hostname: pgconv.Text(in.TargetKey)})
	}
	if err == nil {
		if serr := q.SetHostStatus(ctx, sqlc.SetHostStatusParams{ID: host.ID, Status: sqlc.HostStatus(in.Status)}); serr != nil {
			return sqlc.Host{}, false, serr
		}
		host.Status = sqlc.HostStatus(in.Status)
		return host, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return sqlc.Host{}, false, err
	}
	hostname := pgtype.Text{}
	if !in.IsIP {
		hostname = pgconv.Text(in.TargetKey)
	}
	created, cerr := q.InsertHost(ctx, sqlc.InsertHostParams{
		ProjectID: in.ProjectID, IpAddress: ipValue, Hostname: hostname,
		Status: sqlc.HostStatus(in.Status), OsType: sqlc.HostOsType("UNKNOWN"), Origin: "host",
	})
	if cerr != nil {
		return sqlc.Host{}, false, cerr
	}
	return created, true, nil
}

// ─────────────────────────── PersistHost ───────────────────────────

func (r *Repo) PersistHost(ctx context.Context, in recon.HostPersistInput) (recon.HostPersistOutcome, error) {
	var out recon.HostPersistOutcome
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		host, created, err := r.findOrCreateHost(ctx, q, in)
		if err != nil {
			return err
		}
		out.Created = created
		var newPrimaryIP *string
		if in.HasIP {
			existing, lerr := q.ListHostIPs(ctx, host.ID)
			if lerr != nil {
				return lerr
			}
			primaryID, primaryOK, _, np, eerr := r.ensureIPs(ctx, q, host.ID, existing, in.IPs, in.CloudflareHint, in.CFResponded)
			if eerr != nil {
				return eerr
			}
			newPrimaryIP = np
			if primaryOK && !in.Blocked {
				for _, pw := range in.Ports {
					newPort, perr := r.upsertPort(ctx, q, host.ID, primaryID, pw)
					if perr != nil {
						return perr
					}
					if newPort {
						out.PortsCreated++
					} else {
						out.PortsUpdated++
					}
				}
			}
		}
		out.FinalHostname, out.FinalIPAddress = finalHostFields(host, newPrimaryIP)
		return nil
	})
	if err != nil {
		return recon.HostPersistOutcome{}, err
	}
	return out, nil
}

// ─────────────────────────── PersistIP ───────────────────────────

func (r *Repo) PersistIP(ctx context.Context, in recon.IPPersistInput) (recon.IPPersistOutcome, error) {
	var out recon.IPPersistOutcome
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		host, err := q.GetOriginIPHostByAddress(ctx, sqlc.GetOriginIPHostByAddressParams{ProjectID: in.ProjectID, IpAddress: in.IP})
		created := false
		attached := false
		if err == nil {
			attached = true
		} else if errors.Is(err, pgx.ErrNoRows) {
			host, err = q.InsertHost(ctx, sqlc.InsertHostParams{
				ProjectID: in.ProjectID, IpAddress: pgconv.Text(in.IP), Hostname: pgtype.Text{},
				Status: sqlc.HostStatusUNKNOWN, OsType: sqlc.HostOsType("UNKNOWN"), Origin: "ip",
			})
			if err != nil {
				return err
			}
			created = true
		} else {
			return err
		}
		out.HostCreated = created
		out.Attached = attached

		// Своим строкам фермы IP (origin='ip') ставим статус.
		if err := q.SetHostStatus(ctx, sqlc.SetHostStatusParams{ID: host.ID, Status: sqlc.HostStatus(in.Status)}); err != nil {
			return err
		}
		out.HostID = host.ID

		existing, lerr := q.ListHostIPs(ctx, host.ID)
		if lerr != nil {
			return lerr
		}
		for _, row := range existing {
			if row.IpAddress == in.IP {
				out.IPExisted = true
				break
			}
		}
		primaryID, primaryOK, primaryCF, _, eerr := r.ensureIPs(ctx, q, host.ID, existing, []string{in.IP}, in.CloudflareHint, in.CFResponded)
		if eerr != nil {
			return eerr
		}
		if !primaryOK {
			return errors.New("не удалось завести адрес")
		}
		out.IsCloudflare = primaryCF

		hostnamesJSON, _ := json.Marshal(in.Hostnames)
		if err := q.SetHostIPHostnames(ctx, sqlc.SetHostIPHostnamesParams{ID: primaryID, Hostnames: hostnamesJSON}); err != nil {
			return err
		}

		if !in.Blocked {
			for _, pw := range in.Ports {
				newPort, perr := r.upsertPort(ctx, q, host.ID, primaryID, pw)
				if perr != nil {
					return perr
				}
				if newPort {
					out.PortsCreated++
				} else {
					out.PortsUpdated++
				}
			}
		}
		return nil
	})
	if err != nil {
		return recon.IPPersistOutcome{}, err
	}
	return out, nil
}

// ─────────────────────────── PersistScanHost ───────────────────────────

func (r *Repo) PersistScanHost(ctx context.Context, in recon.ScanHostInput) (recon.ScanHostOutcome, error) {
	var out recon.ScanHostOutcome
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		host, _, err := r.findOrCreateHost(ctx, q, recon.HostPersistInput{
			ProjectID: in.ProjectID, IsIP: in.IsIP, TargetKey: in.TargetKey, Status: in.Status,
			IPs: in.IPs, HasIP: len(in.IPs) > 0,
		})
		if err != nil {
			return err
		}
		existing, lerr := q.ListHostIPs(ctx, host.ID)
		if lerr != nil {
			return lerr
		}
		primaryID, primaryOK, _, newPrimaryIP, eerr := r.ensureIPs(ctx, q, host.ID, existing, in.IPs, false, false)
		if eerr != nil {
			return eerr
		}
		if primaryOK {
			for _, port := range in.OpenPorts {
				newPort, perr := r.upsertScanPort(ctx, q, host.ID, primaryID, int32(port))
				if perr != nil {
					return perr
				}
				if newPort {
					out.PortsCreated++
				} else {
					out.PortsUpdated++
				}
			}
		}
		out.FinalHostname, out.FinalIPAddress = finalHostFields(host, newPrimaryIP)
		return nil
	})
	if err != nil {
		return recon.ScanHostOutcome{}, err
	}
	return out, nil
}

// upsertScanPort — порт как OPEN, НЕ трогая http_status/сервисы (порт _upsert_scan_port).
func (r *Repo) upsertScanPort(ctx context.Context, q *sqlc.Queries, hostID, ipAddrID, portNumber int32) (bool, error) {
	existing, err := q.GetPortByIPNumberProto(ctx, sqlc.GetPortByIPNumberProtoParams{
		IpAddressID: ipAddrID, PortNumber: portNumber, Protocol: sqlc.PortProtocolTCP,
	})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	if err == nil {
		return false, q.SetPortStateOpen(ctx, existing.ID)
	}
	_, ierr := q.InsertPort(ctx, sqlc.InsertPortParams{
		HostID: hostID, IpAddressID: ipAddrID, PortNumber: portNumber,
		Protocol: sqlc.PortProtocolTCP, State: sqlc.PortStateOPEN, HttpStatus: pgtype.Int4{},
	})
	if ierr != nil {
		return false, ierr
	}
	return true, nil
}

// ─────────────────────────── PersistJSFile ───────────────────────────

func (r *Repo) PersistJSFile(ctx context.Context, in recon.JSFileInput) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		endpointsJSON, _ := json.Marshal(orEmptyStrings(in.Endpoints))
		id, err := q.UpsertJsFile(ctx, sqlc.UpsertJsFileParams{
			ProjectID:     in.ProjectID,
			HostID:        in.HostID,
			Url:           in.URL,
			Sha256:        pgconv.Text(in.SHA256),
			SizeBytes:     pgconv.Int4(in.SizeBytes),
			ContentType:   pgconv.Text(in.ContentType),
			Status:        in.Status,
			Error:         pgconv.Text(in.Error),
			SecretCount:   in.SecretCount,
			EndpointCount: in.EndpointCount,
			Endpoints:     endpointsJSON,
			FetchedAt:     pgconv.Ts(time.Now()),
		})
		if err != nil {
			return err
		}
		if err := q.DeleteJsSecretsForFile(ctx, id); err != nil {
			return err
		}
		for _, sec := range in.Secrets {
			if err := q.InsertJsSecret(ctx, sqlc.InsertJsSecretParams{
				JsFileID:     id,
				Kind:         sec.Kind,
				MatchPreview: sec.MatchPreview,
				Snippet:      pgconv.Text(sec.Snippet),
				Severity:     sec.Severity,
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

// ─────────────────────────── выбор целей по проекту ───────────────────────────

func (r *Repo) ProjectDomainHostnames(ctx context.Context, projectID int32) ([]string, error) {
	rows, err := r.q.ListProjectDomainHostnames(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return textList(rows), nil
}

func (r *Repo) ProjectAllHostnames(ctx context.Context, projectID int32) ([]string, error) {
	rows, err := r.q.ListProjectAllHostnames(ctx, projectID)
	if err != nil {
		return nil, err
	}
	return textList(rows), nil
}

func (r *Repo) ProjectOriginIPs(ctx context.Context, projectID int32) ([]string, error) {
	return r.q.ListProjectOriginIPs(ctx, projectID)
}

func (r *Repo) ProjectScanTargets(ctx context.Context, projectID int32) ([]string, error) {
	rows, err := r.q.ListProjectScanTargets(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		target := pgconv.TextVal(row.Hostname)
		if target == "" {
			target = pgconv.TextVal(row.IpAddress)
		}
		if target != "" {
			out = append(out, target)
		}
	}
	return out, nil
}

func (r *Repo) ProjectOriginHostMap(ctx context.Context, projectID int32) (map[string]int32, error) {
	rows, err := r.q.ListProjectOriginHostRows(ctx, projectID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]int32, len(rows))
	for _, row := range rows {
		if !row.Hostname.Valid || row.Hostname.String == "" {
			continue
		}
		key := lower(row.Hostname.String)
		if _, exists := out[key]; !exists { // setdefault: первый выигрывает
			out[key] = row.ID
		}
	}
	return out, nil
}

// ─────────────────────────── js-файлы ───────────────────────────

func (r *Repo) ListJsFiles(ctx context.Context, projectID int32) ([]recon.JSFileView, error) {
	files, err := r.q.ListJsFilesForProject(ctx, projectID)
	if err != nil {
		return nil, err
	}
	nameRows, err := r.q.ListProjectHostIDNames(ctx, projectID)
	if err != nil {
		return nil, err
	}
	names := make(map[int32]*string, len(nameRows))
	for _, nr := range nameRows {
		names[nr.ID] = pgconv.TextValPtr(nr.Hostname)
	}
	out := make([]recon.JSFileView, 0, len(files))
	for _, f := range files {
		secretRows, serr := r.q.ListJsSecretsForFile(ctx, f.ID)
		if serr != nil {
			return nil, serr
		}
		secrets := make([]recon.JSSecretInput, 0, len(secretRows))
		for _, s := range secretRows {
			secrets = append(secrets, recon.JSSecretInput{
				Kind: s.Kind, MatchPreview: s.MatchPreview, Snippet: pgconv.TextVal(s.Snippet), Severity: s.Severity,
			})
		}
		var endpoints []string
		if len(f.Endpoints) > 0 {
			_ = json.Unmarshal(f.Endpoints, &endpoints)
		}
		out = append(out, recon.JSFileView{
			ID: f.ID, HostID: f.HostID, Hostname: names[f.HostID], URL: f.Url, Status: f.Status,
			SizeBytes: pgconv.Int4Val(f.SizeBytes), ContentType: pgconv.TextValPtr(f.ContentType),
			SecretCount: f.SecretCount, EndpointCount: f.EndpointCount, Endpoints: orEmptyStrings(endpoints),
			Secrets: secrets, FetchedAt: pgconv.TsValPtr(f.FetchedAt),
		})
	}
	return out, nil
}

func (r *Repo) JSFileURLs(ctx context.Context, projectID int32, hostID *int32) ([]string, error) {
	if hostID != nil {
		return r.q.ListJsFileURLsForHost(ctx, sqlc.ListJsFileURLsForHostParams{ProjectID: projectID, HostID: *hostID})
	}
	return r.q.ListJsFileURLsForProject(ctx, projectID)
}

// ─────────────────────────── конфигурация фермы ───────────────────────────

// GetFarmConfig отдаёт DefaultFarmConfig, поверх которого наложен сохранённый
// JSONB-блоб (отсутствующие/незнакомые поля остаются дефолтными). Нет строки —
// чистые дефолты.
func (r *Repo) GetFarmConfig(ctx context.Context, projectID int32) (recon.FarmConfig, error) {
	cfg := recon.DefaultFarmConfig()
	blob, err := r.q.GetReconFarmConfig(ctx, projectID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cfg, nil
		}
		return recon.FarmConfig{}, err
	}
	if len(blob) > 0 {
		if err := json.Unmarshal(blob, &cfg); err != nil {
			return recon.FarmConfig{}, err
		}
	}
	return cfg, nil
}

// SaveFarmConfig идемпотентно апсертит конфиг проекта (JSONB-блоб).
func (r *Repo) SaveFarmConfig(ctx context.Context, projectID int32, cfg recon.FarmConfig) error {
	blob, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return r.q.UpsertReconFarmConfig(ctx, sqlc.UpsertReconFarmConfigParams{ProjectID: projectID, Config: blob})
}

// ─────────────────────────── аудит ───────────────────────────

func (r *Repo) InsertAudit(ctx context.Context, e recon.AuditEntry) error {
	return r.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		UserID:     pgconv.Int4(e.UserID),
		Action:     e.Action,
		EntityType: pgconv.Text(e.EntityType),
		EntityID:   pgconv.Int4(e.EntityID),
		Details:    e.Details,
		IpAddress:  pgconv.Text(e.IPAddress),
	})
}

func orEmptyStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// DeleteJSFilesForHost удаляет все JS-файлы хоста в проекте (секреты каскадят).
func (r *Repo) DeleteJSFilesForHost(ctx context.Context, projectID, hostID int32) error {
	return r.q.DeleteJsFilesForHost(ctx, sqlc.DeleteJsFilesForHostParams{ProjectID: projectID, HostID: hostID})
}
