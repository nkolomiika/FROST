// Package reportrepo — сбор данных отчёта поверх sqlc (порт ReportService._collect_project_data).
package reportrepo

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/report"
	"github.com/nkolomiika/frost/internal/apperr"
)

// Repo реализует report.Store.
type Repo struct{ q *sqlc.Queries }

// New создаёт репозиторий поверх пула.
func New(pool *pgxpool.Pool) *Repo { return &Repo{q: sqlc.New(pool)} }

var _ report.Store = (*Repo)(nil)

func fmtDate(t pgtype.Date) *string {
	if !t.Valid {
		return nil
	}
	s := t.Time.Format("2006-01-02")
	return &s
}

func (r *Repo) Collect(ctx context.Context, projectID int32) (*report.Collected, error) {
	proj, err := r.q.GetProjectByID(ctx, projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, apperr.NotFound("Проект не найден")
	}
	if err != nil {
		return nil, err
	}
	col := &report.Collected{
		ProjectName: proj.Name,
		StartDate:   fmtDate(proj.StartDate),
		EndDate:     fmtDate(proj.EndDate),
	}

	// Участники (имена).
	members, err := r.q.ListMembers(ctx, projectID)
	if err != nil {
		return nil, err
	}
	for _, m := range members {
		col.Members = append(col.Members, m.Username)
	}

	// Хосты (все, любого origin).
	hosts, err := r.q.ListHosts(ctx, sqlc.ListHostsParams{ProjectID: projectID, Lim: 100000})
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		col.Hosts = append(col.Hosts, report.HostJSON{
			ID:        h.ID,
			Hostname:  pgconv.TextValPtr(h.Hostname),
			IPAddress: pgconv.TextValPtr(h.IpAddress),
		})
	}

	// Уязвимости (все).
	vulns, err := r.q.ListVulns(ctx, sqlc.ListVulnsParams{ProjectID: projectID, Lim: 100000})
	if err != nil {
		return nil, err
	}
	for _, v := range vulns {
		var cvssVer *string
		if v.CvssVersion.Valid {
			s := string(v.CvssVersion.CvssVersion)
			cvssVer = &s
		}
		ws := json.RawMessage("null")
		if len(v.WorkflowSteps) > 0 {
			ws = json.RawMessage(v.WorkflowSteps)
		}
		col.Vulnerabilities = append(col.Vulnerabilities, report.VulnJSON{
			ID:               v.ID,
			Title:            v.Title,
			Severity:         string(v.Severity),
			CvssVersion:      cvssVer,
			CvssVector:       pgconv.TextValPtr(v.CvssVector),
			CvssScore:        v.CvssScore,
			CweID:            pgconv.TextValPtr(v.CweID),
			Description:      pgconv.TextValPtr(v.Description),
			Impact:           pgconv.TextValPtr(v.Impact),
			Recommendations:  pgconv.TextValPtr(v.Recommendations),
			StepsToReproduce: pgconv.TextValPtr(v.StepsToReproduce),
			WorkflowSteps:    ws,
			Status:           string(v.Status),
			CreatedBy:        v.CreatedBy,
		})

		// Ассеты и файлы находки.
		assets, err := r.q.ListVulnAssets(ctx, v.ID)
		if err != nil {
			return nil, err
		}
		for _, a := range assets {
			col.Assets = append(col.Assets, report.AssetJSON{
				ID: a.ID, VulnerabilityID: a.VulnerabilityID, AssetType: string(a.AssetType), AssetID: a.AssetID,
			})
		}
		files, err := r.q.ListVulnFiles(ctx, v.ID)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			col.Files = append(col.Files, report.FileJSON{
				ID: f.ID, VulnerabilityID: f.VulnerabilityID, ContentType: f.ContentType, OriginalName: f.OriginalName,
			})
			if strings.HasPrefix(f.ContentType, "image/") {
				col.ImageFiles = append(col.ImageFiles, report.ImageFile{ID: f.ID, MinioKey: f.MinioKey})
			}
		}
	}
	return col, nil
}
