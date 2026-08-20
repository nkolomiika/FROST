// Package vulnsrepo — реализация порта vulns.Store поверх sqlc + pgxpool.
// Компаундные операции (создание уязвимости + HOST-связь, комментарий +
// упоминания + уведомления, замена упоминаний) выполняются в транзакции.
package vulnsrepo

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nkolomiika/frost/internal/adapters/postgres/pgconv"
	"github.com/nkolomiika/frost/internal/adapters/postgres/sqlc"
	"github.com/nkolomiika/frost/internal/app/vulns"
)

// Repo реализует vulns.Store.
type Repo struct {
	pool *pgxpool.Pool
	q    *sqlc.Queries
}

// New создаёт репозиторий поверх пула соединений.
func New(pool *pgxpool.Pool) *Repo {
	return &Repo{pool: pool, q: sqlc.New(pool)}
}

var _ vulns.Store = (*Repo)(nil)

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
		return vulns.ErrNoRows
	}
	return err
}

// ─────────────────────────── enum mapping ───────────────────────────

// cvss_version: домен «4.0»/«3.1» ↔ БД-энум V40/V31.
func nullCvssVersion(v *string) sqlc.NullCvssVersion {
	if v == nil {
		return sqlc.NullCvssVersion{}
	}
	switch *v {
	case "4.0":
		return sqlc.NullCvssVersion{CvssVersion: sqlc.CvssVersionV40, Valid: true}
	case "3.1":
		return sqlc.NullCvssVersion{CvssVersion: sqlc.CvssVersionV31, Valid: true}
	default:
		return sqlc.NullCvssVersion{}
	}
}

func cvssVersionToDomain(v sqlc.NullCvssVersion) *string {
	if !v.Valid {
		return nil
	}
	var s string
	switch v.CvssVersion {
	case sqlc.CvssVersionV40:
		s = "4.0"
	case sqlc.CvssVersionV31:
		s = "3.1"
	default:
		return nil
	}
	return &s
}

func nullSeverity(s string) sqlc.NullVulnSeverity {
	if s == "" {
		return sqlc.NullVulnSeverity{}
	}
	return sqlc.NullVulnSeverity{VulnSeverity: sqlc.VulnSeverity(s), Valid: true}
}

func nullStatus(s string) sqlc.NullVulnStatus {
	if s == "" {
		return sqlc.NullVulnStatus{}
	}
	return sqlc.NullVulnStatus{VulnStatus: sqlc.VulnStatus(s), Valid: true}
}

// ─────────────────────────── vulnerabilities ───────────────────────────

func mapVulnRow(
	id, projectID int32, title string, description pgtype.Text,
	severity sqlc.VulnSeverity, cvssVersion sqlc.NullCvssVersion, cvssScore *float64,
	cvssVector, cweID pgtype.Text, status sqlc.VulnStatus, workflowSteps []byte,
	stepsToReproduce, impact, recommendations pgtype.Text, createdBy int32,
	createdAt, updatedAt pgtype.Timestamptz, createdByUsername pgtype.Text,
) *vulns.Vuln {
	return &vulns.Vuln{
		ID:                id,
		ProjectID:         projectID,
		Title:             title,
		Description:       pgconv.TextValPtr(description),
		Severity:          string(severity),
		CvssVersion:       cvssVersionToDomain(cvssVersion),
		CvssScore:         cvssScore,
		CvssVector:        pgconv.TextValPtr(cvssVector),
		CweID:             pgconv.TextValPtr(cweID),
		Status:            string(status),
		WorkflowStepsRaw:  workflowSteps,
		StepsToReproduce:  pgconv.TextValPtr(stepsToReproduce),
		Impact:            pgconv.TextValPtr(impact),
		Recommendations:   pgconv.TextValPtr(recommendations),
		CreatedBy:         createdBy,
		CreatedByUsername: pgconv.TextValPtr(createdByUsername),
		CreatedAt:         pgconv.TsVal(createdAt),
		UpdatedAt:         pgconv.TsVal(updatedAt),
	}
}

func (r *Repo) GetVuln(ctx context.Context, projectID, vulnID int32) (*vulns.Vuln, error) {
	v, err := r.q.GetVuln(ctx, sqlc.GetVulnParams{ID: vulnID, ProjectID: projectID})
	if err != nil {
		return nil, mapErr(err)
	}
	return mapVulnRow(v.ID, v.ProjectID, v.Title, v.Description, v.Severity, v.CvssVersion, v.CvssScore,
		v.CvssVector, v.CweID, v.Status, v.WorkflowSteps, v.StepsToReproduce, v.Impact, v.Recommendations,
		v.CreatedBy, v.CreatedAt, v.UpdatedAt, v.CreatedByUsername), nil
}

func (r *Repo) ListVulns(ctx context.Context, p vulns.VulnListParams) ([]vulns.Vuln, int64, error) {
	rows, err := r.q.ListVulns(ctx, sqlc.ListVulnsParams{
		ProjectID: p.ProjectID, Severity: nullSeverity(p.Severity), Status: nullStatus(p.Status),
		Offset: p.Offset, Lim: p.Limit,
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := r.q.CountVulns(ctx, sqlc.CountVulnsParams{
		ProjectID: p.ProjectID, Severity: nullSeverity(p.Severity), Status: nullStatus(p.Status),
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]vulns.Vuln, 0, len(rows))
	for _, v := range rows {
		out = append(out, *mapVulnRow(v.ID, v.ProjectID, v.Title, v.Description, v.Severity, v.CvssVersion, v.CvssScore,
			v.CvssVector, v.CweID, v.Status, v.WorkflowSteps, v.StepsToReproduce, v.Impact, v.Recommendations,
			v.CreatedBy, v.CreatedAt, v.UpdatedAt, v.CreatedByUsername))
	}
	return out, total, nil
}

func (r *Repo) ListVulnsForHost(ctx context.Context, p vulns.VulnHostListParams) ([]vulns.Vuln, int64, error) {
	rows, err := r.q.ListVulnsForHost(ctx, sqlc.ListVulnsForHostParams{
		HostID: p.HostID, ProjectID: p.ProjectID, Severity: nullSeverity(p.Severity), Status: nullStatus(p.Status),
		Offset: p.Offset, Lim: p.Limit,
	})
	if err != nil {
		return nil, 0, err
	}
	total, err := r.q.CountVulnsForHost(ctx, sqlc.CountVulnsForHostParams{
		HostID: p.HostID, ProjectID: p.ProjectID, Severity: nullSeverity(p.Severity), Status: nullStatus(p.Status),
	})
	if err != nil {
		return nil, 0, err
	}
	out := make([]vulns.Vuln, 0, len(rows))
	for _, v := range rows {
		out = append(out, *mapVulnRow(v.ID, v.ProjectID, v.Title, v.Description, v.Severity, v.CvssVersion, v.CvssScore,
			v.CvssVector, v.CweID, v.Status, v.WorkflowSteps, v.StepsToReproduce, v.Impact, v.Recommendations,
			v.CreatedBy, v.CreatedAt, v.UpdatedAt, v.CreatedByUsername))
	}
	return out, total, nil
}

func (r *Repo) HostExistsInProject(ctx context.Context, hostID, projectID int32) (bool, error) {
	return r.q.HostExistsInProject(ctx, sqlc.HostExistsInProjectParams{ID: hostID, ProjectID: projectID})
}

func insertVulnParams(projectID, createdBy int32, w vulns.VulnWrite) sqlc.InsertVulnParams {
	return sqlc.InsertVulnParams{
		ProjectID:        projectID,
		Title:            w.Title,
		Description:      pgconv.TextPtr(w.Description),
		Severity:         sqlc.VulnSeverity(w.Severity),
		CvssVersion:      nullCvssVersion(w.CvssVersion),
		CvssScore:        w.CvssScore,
		CvssVector:       pgconv.TextPtr(w.CvssVector),
		CweID:            pgconv.TextPtr(w.CweID),
		Status:           sqlc.VulnStatus(w.Status),
		WorkflowSteps:    w.WorkflowSteps,
		StepsToReproduce: pgconv.TextPtr(w.StepsToReproduce),
		Impact:           pgconv.TextPtr(w.Impact),
		Recommendations:  pgconv.TextPtr(w.Recommendations),
		CreatedBy:        createdBy,
	}
}

func (r *Repo) CreateVuln(ctx context.Context, nv vulns.NewVuln) (int32, error) {
	var newID int32
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		v, err := q.InsertVuln(ctx, insertVulnParams(nv.ProjectID, nv.CreatedBy, nv.Fields))
		if err != nil {
			return err
		}
		newID = v.ID
		_, err = q.InsertVulnAsset(ctx, sqlc.InsertVulnAssetParams{
			VulnerabilityID: v.ID, AssetType: sqlc.AssetTypeHOST, AssetID: nv.HostID,
		})
		return err
	})
	if err != nil {
		return 0, err
	}
	return newID, nil
}

func (r *Repo) UpdateVuln(ctx context.Context, id int32, w vulns.VulnWrite) error {
	_, err := r.q.UpdateVuln(ctx, sqlc.UpdateVulnParams{
		ID:               id,
		Title:            w.Title,
		Description:      pgconv.TextPtr(w.Description),
		Severity:         sqlc.VulnSeverity(w.Severity),
		CvssVersion:      nullCvssVersion(w.CvssVersion),
		CvssScore:        w.CvssScore,
		CvssVector:       pgconv.TextPtr(w.CvssVector),
		CweID:            pgconv.TextPtr(w.CweID),
		Status:           sqlc.VulnStatus(w.Status),
		WorkflowSteps:    w.WorkflowSteps,
		StepsToReproduce: pgconv.TextPtr(w.StepsToReproduce),
		Impact:           pgconv.TextPtr(w.Impact),
		Recommendations:  pgconv.TextPtr(w.Recommendations),
	})
	return mapErr(err)
}

func (r *Repo) PatchVulnStatus(ctx context.Context, id int32, status string) error {
	_, err := r.q.PatchVulnStatus(ctx, sqlc.PatchVulnStatusParams{ID: id, Status: sqlc.VulnStatus(status)})
	return mapErr(err)
}

func (r *Repo) DeleteVuln(ctx context.Context, id int32) error {
	return r.q.DeleteVuln(ctx, id)
}

// VulnProjectID — project_id уязвимости по её id (для download-проверки доступа;
// среди доступных sqlc-запросов нет выборки vuln по одному id).
func (r *Repo) VulnProjectID(ctx context.Context, vulnID int32) (int32, error) {
	var projectID int32
	err := r.pool.QueryRow(ctx, "SELECT project_id FROM vulnerabilities WHERE id = $1", vulnID).Scan(&projectID)
	if err != nil {
		return 0, mapErr(err)
	}
	return projectID, nil
}

// ─────────────────────────── assets ───────────────────────────

func mapAssetLink(a sqlc.VulnerabilityAsset) vulns.AssetLink {
	return vulns.AssetLink{ID: a.ID, VulnerabilityID: a.VulnerabilityID, AssetType: string(a.AssetType), AssetID: a.AssetID}
}

func (r *Repo) ListVulnAssets(ctx context.Context, vulnID int32) ([]vulns.AssetLink, error) {
	rows, err := r.q.ListVulnAssets(ctx, vulnID)
	if err != nil {
		return nil, err
	}
	out := make([]vulns.AssetLink, 0, len(rows))
	for _, a := range rows {
		out = append(out, mapAssetLink(a))
	}
	return out, nil
}

func (r *Repo) FindVulnAsset(ctx context.Context, vulnID int32, assetType string, assetID int32) (bool, error) {
	_, err := r.q.FindVulnAsset(ctx, sqlc.FindVulnAssetParams{
		VulnerabilityID: vulnID, AssetType: sqlc.AssetType(assetType), AssetID: assetID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (r *Repo) GetVulnAssetLink(ctx context.Context, linkID, vulnID int32) (*vulns.AssetLink, error) {
	a, err := r.q.GetVulnAssetLink(ctx, sqlc.GetVulnAssetLinkParams{ID: linkID, VulnerabilityID: vulnID})
	if err != nil {
		return nil, mapErr(err)
	}
	link := mapAssetLink(a)
	return &link, nil
}

func (r *Repo) CountHostAssetLinks(ctx context.Context, vulnID int32) (int64, error) {
	return r.q.CountHostAssetLinks(ctx, vulnID)
}

func (r *Repo) InsertVulnAsset(ctx context.Context, vulnID int32, assetType string, assetID int32) (*vulns.AssetLink, error) {
	a, err := r.q.InsertVulnAsset(ctx, sqlc.InsertVulnAssetParams{
		VulnerabilityID: vulnID, AssetType: sqlc.AssetType(assetType), AssetID: assetID,
	})
	if err != nil {
		return nil, err
	}
	link := mapAssetLink(a)
	return &link, nil
}

func (r *Repo) DeleteVulnAsset(ctx context.Context, linkID int32) error {
	return r.q.DeleteVulnAsset(ctx, linkID)
}

func (r *Repo) AssetInProject(ctx context.Context, assetType string, assetID, projectID int32) (bool, error) {
	switch assetType {
	case vulns.AssetHost:
		return r.q.HostAssetInProject(ctx, sqlc.HostAssetInProjectParams{ID: assetID, ProjectID: projectID})
	case vulns.AssetPort:
		return r.q.PortAssetInProject(ctx, sqlc.PortAssetInProjectParams{ID: assetID, ProjectID: projectID})
	case vulns.AssetService:
		return r.q.ServiceAssetInProject(ctx, sqlc.ServiceAssetInProjectParams{ID: assetID, ProjectID: projectID})
	case vulns.AssetEndpoint:
		return r.q.EndpointAssetInProject(ctx, sqlc.EndpointAssetInProjectParams{ID: assetID, ProjectID: projectID})
	default:
		return false, nil
	}
}

func (r *Repo) PrimaryHostID(ctx context.Context, vulnID int32) (int32, bool, error) {
	hostID, err := r.q.PrimaryHostID(ctx, vulnID)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return hostID, true, nil
}

// ─────────────────────────── comments ───────────────────────────

func (r *Repo) CountVulnComments(ctx context.Context, vulnID int32) (int64, error) {
	return r.q.CountVulnComments(ctx, vulnID)
}

func (r *Repo) ListVulnComments(ctx context.Context, vulnID, offset, limit int32) ([]vulns.Comment, error) {
	rows, err := r.q.ListVulnComments(ctx, sqlc.ListVulnCommentsParams{VulnerabilityID: vulnID, Offset: offset, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]vulns.Comment, 0, len(rows))
	for _, c := range rows {
		out = append(out, vulns.Comment{
			ID:               c.ID,
			VulnerabilityID:  c.VulnerabilityID,
			UserID:           c.UserID,
			Username:         c.Username,
			AvatarKey:        pgconv.TextValPtr(c.AvatarMinioKey),
			AvatarUploadedAt: pgconv.TsValPtr(c.AvatarUploadedAt),
			Content:          c.Content,
			CreatedAt:        pgconv.TsVal(c.CreatedAt),
			UpdatedAt:        pgconv.TsVal(c.UpdatedAt),
		})
	}
	return out, nil
}

func (r *Repo) ListCommentMentions(ctx context.Context, commentID int32) ([]vulns.Mention, error) {
	rows, err := r.q.ListCommentMentions(ctx, commentID)
	if err != nil {
		return nil, err
	}
	out := make([]vulns.Mention, 0, len(rows))
	for _, m := range rows {
		out = append(out, vulns.Mention{UserID: m.UserID, Username: m.Username})
	}
	return out, nil
}

func (r *Repo) GetVulnComment(ctx context.Context, commentID, vulnID int32) (*vulns.Comment, error) {
	c, err := r.q.GetVulnComment(ctx, sqlc.GetVulnCommentParams{ID: commentID, VulnerabilityID: vulnID})
	if err != nil {
		return nil, mapErr(err)
	}
	return &vulns.Comment{
		ID: c.ID, VulnerabilityID: c.VulnerabilityID, UserID: c.UserID, Content: c.Content,
		CreatedAt: pgconv.TsVal(c.CreatedAt), UpdatedAt: pgconv.TsVal(c.UpdatedAt),
	}, nil
}

func (r *Repo) ResolveCommentMentionUsers(ctx context.Context, projectID int32, usernames []string) ([]vulns.Mention, error) {
	rows, err := r.q.ResolveCommentMentionUsers(ctx, sqlc.ResolveCommentMentionUsersParams{ProjectID: projectID, Usernames: usernames})
	if err != nil {
		return nil, err
	}
	out := make([]vulns.Mention, 0, len(rows))
	for _, u := range rows {
		out = append(out, vulns.Mention{UserID: u.ID, Username: u.Username})
	}
	return out, nil
}

func (r *Repo) CreateComment(ctx context.Context, d vulns.CommentCreateData) (*vulns.Comment, error) {
	var out *vulns.Comment
	err := r.tx(ctx, func(q *sqlc.Queries) error {
		c, err := q.InsertVulnComment(ctx, sqlc.InsertVulnCommentParams{VulnerabilityID: d.VulnID, UserID: d.UserID, Content: d.Content})
		if err != nil {
			return err
		}
		for _, m := range d.Mentions {
			if err := q.InsertCommentMention(ctx, sqlc.InsertCommentMentionParams{CommentID: c.ID, UserID: m.UserID}); err != nil {
				return err
			}
		}
		for _, uid := range d.Notify {
			if err := q.InsertMentionNotification(ctx, sqlc.InsertMentionNotificationParams{
				UserID: uid, CommentID: pgconv.Int4(&c.ID), ActorID: pgconv.Int4(&d.ActorID),
			}); err != nil {
				return err
			}
		}
		out = &vulns.Comment{
			ID: c.ID, VulnerabilityID: c.VulnerabilityID, UserID: c.UserID, Content: c.Content,
			CreatedAt: pgconv.TsVal(c.CreatedAt), UpdatedAt: pgconv.TsVal(c.UpdatedAt),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *Repo) UpdateCommentWithMentions(ctx context.Context, commentID int32, content string, mentions []vulns.Mention) error {
	return r.tx(ctx, func(q *sqlc.Queries) error {
		if err := q.UpdateVulnComment(ctx, sqlc.UpdateVulnCommentParams{ID: commentID, Content: content}); err != nil {
			return err
		}
		if err := q.ClearCommentMentions(ctx, commentID); err != nil {
			return err
		}
		for _, m := range mentions {
			if err := q.InsertCommentMention(ctx, sqlc.InsertCommentMentionParams{CommentID: commentID, UserID: m.UserID}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *Repo) DeleteVulnComment(ctx context.Context, id int32) error {
	return r.q.DeleteVulnComment(ctx, id)
}

// ─────────────────────────── files ───────────────────────────

func mapFile(f sqlc.File) vulns.File {
	return vulns.File{
		ID:              f.ID,
		VulnerabilityID: f.VulnerabilityID,
		OriginalName:    f.OriginalName,
		ContentType:     f.ContentType,
		SizeBytes:       f.SizeBytes,
		MinioBucket:     f.MinioBucket,
		MinioKey:        f.MinioKey,
		UploadedBy:      f.UploadedBy,
		UploadedAt:      pgconv.TsVal(f.UploadedAt),
	}
}

func (r *Repo) ListVulnFiles(ctx context.Context, vulnID int32) ([]vulns.File, error) {
	rows, err := r.q.ListVulnFiles(ctx, vulnID)
	if err != nil {
		return nil, err
	}
	out := make([]vulns.File, 0, len(rows))
	for _, f := range rows {
		out = append(out, mapFile(f))
	}
	return out, nil
}

func (r *Repo) GetFileByID(ctx context.Context, id int32) (*vulns.File, error) {
	f, err := r.q.GetFileByID(ctx, id)
	if err != nil {
		return nil, mapErr(err)
	}
	file := mapFile(f)
	return &file, nil
}

func (r *Repo) GetFileForVuln(ctx context.Context, id, vulnID int32) (*vulns.File, error) {
	f, err := r.q.GetFileForVuln(ctx, sqlc.GetFileForVulnParams{ID: id, VulnerabilityID: vulnID})
	if err != nil {
		return nil, mapErr(err)
	}
	file := mapFile(f)
	return &file, nil
}

func (r *Repo) InsertFile(ctx context.Context, nf vulns.NewFile) (*vulns.File, error) {
	f, err := r.q.InsertFile(ctx, sqlc.InsertFileParams{
		VulnerabilityID: nf.VulnerabilityID,
		OriginalName:    nf.OriginalName,
		ContentType:     nf.ContentType,
		SizeBytes:       nf.SizeBytes,
		MinioBucket:     nf.MinioBucket,
		MinioKey:        nf.MinioKey,
		UploadedBy:      nf.UploadedBy,
	})
	if err != nil {
		return nil, err
	}
	file := mapFile(f)
	return &file, nil
}

func (r *Repo) DeleteFile(ctx context.Context, id int32) error {
	return r.q.DeleteFile(ctx, id)
}

func (r *Repo) CountFileImagesForVuln(ctx context.Context, vulnID int32, ids []int32) (int64, error) {
	return r.q.CountFileImagesForVuln(ctx, sqlc.CountFileImagesForVulnParams{VulnerabilityID: vulnID, Ids: ids})
}

// ─────────────────────────── membership + notifications + audit ───────────────────────────

func (r *Repo) IsProjectMember(ctx context.Context, projectID, userID int32) (bool, error) {
	return r.q.IsProjectMember(ctx, sqlc.IsProjectMemberParams{ProjectID: projectID, UserID: userID})
}

func (r *Repo) InsertVulnStatusNotification(ctx context.Context, userID, vulnID, projectID, actorID int32, status string) error {
	return r.q.InsertVulnStatusNotification(ctx, sqlc.InsertVulnStatusNotificationParams{
		UserID:          userID,
		VulnerabilityID: pgconv.Int4(&vulnID),
		ProjectID:       pgconv.Int4(&projectID),
		ActorID:         pgconv.Int4(&actorID),
		Status:          pgconv.Text(status),
	})
}

func (r *Repo) InsertAudit(ctx context.Context, e vulns.AuditEntry) error {
	return r.q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
		UserID:     pgconv.Int4(e.UserID),
		Action:     e.Action,
		EntityType: pgconv.Text(e.EntityType),
		EntityID:   pgconv.Int4(e.EntityID),
		Details:    e.Details,
		IpAddress:  pgconv.Text(""),
	})
}
