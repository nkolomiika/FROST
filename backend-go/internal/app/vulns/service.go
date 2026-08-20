package vulns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/nkolomiika/frost/internal/apperr"
)

// maxFileSize — предел размера загружаемого файла (порт MAX_FILE_SIZE).
const maxFileSize = 50 * 1024 * 1024

// allowedMIME — множество допустимых MIME-типов (порт ALLOWED_MIME_TYPES). Тип
// определяется по БАЙТАМ содержимого, а не по заголовку клиента.
var allowedMIME = map[string]bool{
	"image/png":         true,
	"image/jpeg":        true,
	"image/gif":         true,
	"image/webp":        true,
	"text/plain":        true,
	"application/pdf":   true,
	"application/xml":   true,
	"application/json":  true,
	"application/zip":   true,
	"application/x-tar": true,
	"application/gzip":  true,
}

// mentionRe — распознаёт @упоминания (порт MENTION_RE).
var mentionRe = regexp.MustCompile(`@([a-zA-Z0-9_.-]{1,100})`)

// Service — use-cases контекста vulns. Зависит только от портов.
type Service struct {
	store   Store
	storage Storage
	bucket  string
}

// NewService собирает сервис. bucket — имя bucket'а MinIO (пишется в files.minio_bucket).
func NewService(store Store, storage Storage, bucket string) *Service {
	return &Service{store: store, storage: storage, bucket: bucket}
}

// ─────────────────────────── vulnerabilities ───────────────────────────

func (s *Service) getVuln(ctx context.Context, projectID, vulnID int32) (*Vuln, error) {
	v, err := s.store.GetVuln(ctx, projectID, vulnID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Уязвимость не найдена")
	}
	if err != nil {
		return nil, err
	}
	hydrateWorkflowSteps(v)
	return v, nil
}

// ListVulns — список уязвимостей проекта (пагинация + фильтры severity/status).
func (s *Service) ListVulns(ctx context.Context, projectID int32, page, size int, severityFilter, statusFilter string) ([]Vuln, int64, error) {
	sev, ok := mapEnumFilter(severityFilter, validSeverities)
	if !ok {
		return []Vuln{}, 0, nil
	}
	st, ok := mapEnumFilter(statusFilter, validStatuses)
	if !ok {
		return []Vuln{}, 0, nil
	}
	items, total, err := s.store.ListVulns(ctx, VulnListParams{
		ProjectID: projectID, Severity: sev, Status: st,
		Offset: int32((page - 1) * size), Limit: int32(size),
	})
	if err != nil {
		return nil, 0, err
	}
	for i := range items {
		hydrateWorkflowSteps(&items[i])
	}
	return items, total, nil
}

// ListHostVulns — уязвимости, привязанные к конкретному хосту (host-exists → 404).
func (s *Service) ListHostVulns(ctx context.Context, projectID, hostID int32, page, size int, severityFilter, statusFilter string) ([]Vuln, int64, error) {
	exists, err := s.store.HostExistsInProject(ctx, hostID, projectID)
	if err != nil {
		return nil, 0, err
	}
	if !exists {
		return nil, 0, apperr.NotFound("Хост не найден")
	}
	sev, ok := mapEnumFilter(severityFilter, validSeverities)
	if !ok {
		return []Vuln{}, 0, nil
	}
	st, ok := mapEnumFilter(statusFilter, validStatuses)
	if !ok {
		return []Vuln{}, 0, nil
	}
	items, total, err := s.store.ListVulnsForHost(ctx, VulnHostListParams{
		ProjectID: projectID, HostID: hostID, Severity: sev, Status: st,
		Offset: int32((page - 1) * size), Limit: int32(size),
	})
	if err != nil {
		return nil, 0, err
	}
	for i := range items {
		hydrateWorkflowSteps(&items[i])
	}
	return items, total, nil
}

// CreateVuln — порт VulnerabilityService.create. payload — map с ключами как в
// model_dump() (все поля присутствуют: severity/status/workflow_steps есть всегда).
func (s *Service) CreateVuln(ctx context.Context, projectID int32, payload map[string]any, actor Actor) (*Vuln, error) {
	hostID := toInt32(payload["host_id"])
	delete(payload, "host_id")
	if hostID == 0 {
		return nil, apperr.Validation("Уязвимость должна быть привязана к конкретному хосту")
	}
	inProj, err := s.store.AssetInProject(ctx, AssetHost, hostID, projectID)
	if err != nil {
		return nil, err
	}
	if !inProj {
		return nil, apperr.Validation("Актив не найден или принадлежит другому проекту")
	}

	if err := applyCalculatedCvssFields(payload, nil, nil); err != nil {
		return nil, err
	}
	if v, ok := payload["cvss_score"]; ok && v != nil {
		payload["severity"] = severityFromCvssScore(asFloatPtr(v))
	}

	var wfBytes []byte
	if raw, ok := payload["workflow_steps"]; ok {
		steps := normalizeWorkflowSteps(toWorkflowSteps(raw))
		// TODO(phase2): _resolve_workflow_step_endpoints — валидация endpoint_id
		// по хосту и разбор endpoint_request_raw (нет sqlc-запросов для endpoints).
		if err := s.validateWorkflowStepImages(ctx, nil, steps); err != nil {
			return nil, err
		}
		payload["steps_to_reproduce"] = strOrNil(workflowStepsToText(steps))
		wfBytes = mustMarshalSteps(steps)
	}

	fields := VulnWrite{
		Title:            strVal(payload["title"]),
		Description:      asStrPtr(payload["description"]),
		Severity:         strVal(payload["severity"]),
		CvssVersion:      asStrPtr(payload["cvss_version"]),
		CvssScore:        asFloatPtr(payload["cvss_score"]),
		CvssVector:       asStrPtr(payload["cvss_vector"]),
		CweID:            asStrPtr(payload["cwe_id"]),
		Status:           strVal(payload["status"]),
		WorkflowSteps:    wfBytes,
		StepsToReproduce: asStrPtr(payload["steps_to_reproduce"]),
		Impact:           asStrPtr(payload["impact"]),
		Recommendations:  asStrPtr(payload["recommendations"]),
	}
	id, err := s.store.CreateVuln(ctx, NewVuln{ProjectID: projectID, CreatedBy: actor.ID, HostID: hostID, Fields: fields})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{
		UserID: &actor.ID, Action: "CREATE", EntityType: "vulnerability", EntityID: &id,
		Details: mustJSON(map[string]any{"host_id": strconv.Itoa(int(hostID))}),
	})
	// TODO(phase2): ws broadcast (vulnerability created)
	return s.getVuln(ctx, projectID, id)
}

// GetVulnDetail — карточка уязвимости + связанные активы/файлы/число комментариев.
func (s *Service) GetVulnDetail(ctx context.Context, projectID, vulnID int32) (*VulnDetail, error) {
	vuln, err := s.getVuln(ctx, projectID, vulnID)
	if err != nil {
		return nil, err
	}
	assets, err := s.store.ListVulnAssets(ctx, vuln.ID)
	if err != nil {
		return nil, err
	}
	files, err := s.store.ListVulnFiles(ctx, vuln.ID)
	if err != nil {
		return nil, err
	}
	count, err := s.store.CountVulnComments(ctx, vuln.ID)
	if err != nil {
		return nil, err
	}
	return &VulnDetail{Vuln: vuln, Assets: assets, Files: files, CommentsCount: count}, nil
}

// UpdateVuln — порт VulnerabilityService.update. payload — map (exclude_unset:
// только присланные ключи присутствуют).
func (s *Service) UpdateVuln(ctx context.Context, projectID, vulnID int32, payload map[string]any, actor Actor) (*Vuln, error) {
	vuln, err := s.getVuln(ctx, projectID, vulnID)
	if err != nil {
		return nil, err
	}
	oldStatus := vuln.Status

	if err := applyCalculatedCvssFields(payload, vuln.CvssVersion, vuln.CvssVector); err != nil {
		return nil, err
	}
	nextScore := vuln.CvssScore
	if v, ok := payload["cvss_score"]; ok {
		nextScore = asFloatPtr(v)
	}
	if nextScore != nil {
		payload["severity"] = severityFromCvssScore(nextScore)
	}

	wfProcessed := false
	var wfBytes []byte
	if raw, ok := payload["workflow_steps"]; ok {
		steps := normalizeWorkflowSteps(toWorkflowSteps(raw))
		if _, found, err := s.store.PrimaryHostID(ctx, vuln.ID); err != nil {
			return nil, err
		} else if !found {
			return nil, apperr.Validation("Уязвимость должна быть привязана хотя бы к одному хосту")
		}
		// TODO(phase2): _resolve_workflow_step_endpoints (см. CreateVuln).
		if err := s.validateWorkflowStepImages(ctx, &vuln.ID, steps); err != nil {
			return nil, err
		}
		payload["steps_to_reproduce"] = strOrNil(workflowStepsToText(steps))
		wfBytes = mustMarshalSteps(steps)
		wfProcessed = true
	}

	w := VulnWrite{
		Title:            vuln.Title,
		Description:      vuln.Description,
		Severity:         vuln.Severity,
		CvssVersion:      vuln.CvssVersion,
		CvssScore:        vuln.CvssScore,
		CvssVector:       vuln.CvssVector,
		CweID:            vuln.CweID,
		Status:           vuln.Status,
		WorkflowSteps:    vuln.WorkflowStepsRaw,
		StepsToReproduce: vuln.StepsToReproduce,
		Impact:           vuln.Impact,
		Recommendations:  vuln.Recommendations,
	}
	clearable := map[string]bool{
		"description": true, "cvss_version": true, "cvss_score": true,
		"cvss_vector": true, "cwe_id": true, "impact": true, "recommendations": true,
	}
	set := func(key string) bool {
		v, ok := payload[key]
		if !ok {
			return false
		}
		return clearable[key] || v != nil
	}
	if set("title") {
		w.Title = strVal(payload["title"])
	}
	if set("description") {
		w.Description = asStrPtr(payload["description"])
	}
	if set("severity") {
		w.Severity = strVal(payload["severity"])
	}
	if set("cvss_version") {
		w.CvssVersion = asStrPtr(payload["cvss_version"])
	}
	if set("cvss_score") {
		w.CvssScore = asFloatPtr(payload["cvss_score"])
	}
	if set("cvss_vector") {
		w.CvssVector = asStrPtr(payload["cvss_vector"])
	}
	if set("cwe_id") {
		w.CweID = asStrPtr(payload["cwe_id"])
	}
	if set("status") {
		w.Status = strVal(payload["status"])
	}
	if wfProcessed {
		w.WorkflowSteps = wfBytes
		w.StepsToReproduce = asStrPtr(payload["steps_to_reproduce"])
	} else if set("steps_to_reproduce") {
		w.StepsToReproduce = asStrPtr(payload["steps_to_reproduce"])
	}
	if set("impact") {
		w.Impact = asStrPtr(payload["impact"])
	}
	if set("recommendations") {
		w.Recommendations = asStrPtr(payload["recommendations"])
	}

	if err := s.store.UpdateVuln(ctx, vuln.ID, w); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "UPDATE", EntityType: "vulnerability", EntityID: &vuln.ID})
	// TODO(phase2): ws broadcast (vulnerability updated)
	updated, err := s.getVuln(ctx, projectID, vuln.ID)
	if err != nil {
		return nil, err
	}
	if oldStatus != updated.Status {
		if err := s.notifyStatusChanged(ctx, updated, actor.ID); err != nil {
			return nil, err
		}
	}
	return updated, nil
}

// PatchStatus — порт VulnerabilityService.patch_status. statusDB — БД-регистр.
func (s *Service) PatchStatus(ctx context.Context, projectID, vulnID int32, statusDB string, actor Actor) (*Vuln, error) {
	vuln, err := s.getVuln(ctx, projectID, vulnID)
	if err != nil {
		return nil, err
	}
	oldStatus := vuln.Status
	if err := s.store.PatchVulnStatus(ctx, vuln.ID, statusDB); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{
		UserID: &actor.ID, Action: "STATUS_CHANGE", EntityType: "vulnerability", EntityID: &vuln.ID,
		Details: mustJSON(map[string]any{"old_status": strings.ToLower(oldStatus), "new_status": strings.ToLower(statusDB)}),
	})
	// TODO(phase2): ws broadcast (vulnerability updated)
	updated, err := s.getVuln(ctx, projectID, vuln.ID)
	if err != nil {
		return nil, err
	}
	if oldStatus != updated.Status {
		if err := s.notifyStatusChanged(ctx, updated, actor.ID); err != nil {
			return nil, err
		}
	}
	return updated, nil
}

// notifyStatusChanged — повод №3: статус находки изменился, уведомляем автора
// (только если менял кто-то другой). Статус хранится в нижнем регистре.
func (s *Service) notifyStatusChanged(ctx context.Context, vuln *Vuln, actorID int32) error {
	if vuln.CreatedBy == actorID {
		return nil
	}
	if err := s.store.InsertVulnStatusNotification(ctx, vuln.CreatedBy, vuln.ID, vuln.ProjectID, actorID, strings.ToLower(vuln.Status)); err != nil {
		return err
	}
	// TODO(phase2): ws notify_user (notification)
	return nil
}

// DeleteVuln — удаляет уязвимость.
func (s *Service) DeleteVuln(ctx context.Context, projectID, vulnID int32, actor Actor) error {
	vuln, err := s.getVuln(ctx, projectID, vulnID)
	if err != nil {
		return err
	}
	details := mustJSON(map[string]any{
		"project_id": strconv.Itoa(int(projectID)),
		"title":      vuln.Title,
		"severity":   strings.ToLower(vuln.Severity),
	})
	if err := s.store.DeleteVuln(ctx, vuln.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "DELETE", EntityType: "vulnerability", EntityID: &vulnID, Details: details})
	// TODO(phase2): ws broadcast (vulnerability deleted)
	return nil
}

// ─────────────────────────── assets ───────────────────────────

// ListAssets — привязанные активы уязвимости.
func (s *Service) ListAssets(ctx context.Context, projectID, vulnID int32) ([]AssetLink, error) {
	if _, err := s.getVuln(ctx, projectID, vulnID); err != nil {
		return nil, err
	}
	return s.store.ListVulnAssets(ctx, vulnID)
}

// AddAsset — привязывает актив к уязвимости (полиморфная проверка проекта, дубль → 409).
func (s *Service) AddAsset(ctx context.Context, projectID, vulnID int32, assetTypeDB string, assetID int32, actor Actor) (*AssetLink, error) {
	if _, err := s.getVuln(ctx, projectID, vulnID); err != nil {
		return nil, err
	}
	inProj, err := s.store.AssetInProject(ctx, assetTypeDB, assetID, projectID)
	if err != nil {
		return nil, err
	}
	if !inProj {
		return nil, apperr.Validation("Актив не найден или принадлежит другому проекту")
	}
	dup, err := s.store.FindVulnAsset(ctx, vulnID, assetTypeDB, assetID)
	if err != nil {
		return nil, err
	}
	if dup {
		return nil, apperr.Conflict("Связь уже существует")
	}
	link, err := s.store.InsertVulnAsset(ctx, vulnID, assetTypeDB, assetID)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "CREATE", EntityType: "vulnerability_asset", EntityID: &link.ID})
	// TODO(phase2): ws broadcast (vulnerability updated)
	return link, nil
}

// DeleteAsset — удаляет связь (нельзя убрать последнюю HOST-связь).
func (s *Service) DeleteAsset(ctx context.Context, projectID, vulnID, linkID int32, actor Actor) error {
	if _, err := s.getVuln(ctx, projectID, vulnID); err != nil {
		return err
	}
	link, err := s.store.GetVulnAssetLink(ctx, linkID, vulnID)
	if errors.Is(err, ErrNoRows) {
		return apperr.NotFound("Связь не найдена")
	}
	if err != nil {
		return err
	}
	if link.AssetType == AssetHost {
		count, err := s.store.CountHostAssetLinks(ctx, vulnID)
		if err != nil {
			return err
		}
		if count <= 1 {
			return apperr.Validation("Уязвимость должна оставаться привязанной хотя бы к одному хосту")
		}
	}
	if err := s.store.DeleteVulnAsset(ctx, linkID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "DELETE", EntityType: "vulnerability_asset", EntityID: &linkID})
	// TODO(phase2): ws broadcast (vulnerability updated)
	return nil
}

// ─────────────────────────── comments ───────────────────────────

// ListComments — комментарии уязвимости (без guard существования — как в Python).
func (s *Service) ListComments(ctx context.Context, vulnID int32, page, size int) ([]Comment, int64, error) {
	total, err := s.store.CountVulnComments(ctx, vulnID)
	if err != nil {
		return nil, 0, err
	}
	items, err := s.store.ListVulnComments(ctx, vulnID, int32((page-1)*size), int32(size))
	if err != nil {
		return nil, 0, err
	}
	for i := range items {
		mentions, err := s.store.ListCommentMentions(ctx, items[i].ID)
		if err != nil {
			return nil, 0, err
		}
		items[i].Mentions = mentions
	}
	return items, total, nil
}

// CreateComment — добавляет комментарий, строит упоминания и MENTION-уведомления
// (не себе). Упоминание себя даёт строку comment_mentions, но не уведомление.
func (s *Service) CreateComment(ctx context.Context, projectID, vulnID int32, content string, actor Actor) (*Comment, error) {
	if _, err := s.getVuln(ctx, projectID, vulnID); err != nil {
		return nil, err
	}
	mentioned, err := s.resolveMentions(ctx, projectID, content)
	if err != nil {
		return nil, err
	}
	notify := make([]int32, 0, len(mentioned))
	for _, m := range mentioned {
		if m.UserID != actor.ID {
			notify = append(notify, m.UserID)
		}
	}
	comment, err := s.store.CreateComment(ctx, CommentCreateData{
		VulnID: vulnID, UserID: actor.ID, Content: content, Mentions: mentioned, Notify: notify, ActorID: actor.ID,
	})
	if err != nil {
		return nil, err
	}
	// TODO(phase2): ws notify_user (mention) + broadcast (comment created)
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "CREATE", EntityType: "comment", EntityID: &comment.ID})
	comment.Username = actor.Username
	comment.Mentions = mentioned
	return comment, nil
}

// UpdateComment — редактирует свой комментарий; упоминания перестраиваются, но
// новые уведомления не создаются.
func (s *Service) UpdateComment(ctx context.Context, projectID, vulnID, commentID int32, content string, actor Actor) (*Comment, error) {
	if _, err := s.getVuln(ctx, projectID, vulnID); err != nil {
		return nil, err
	}
	comment, err := s.store.GetVulnComment(ctx, commentID, vulnID)
	if errors.Is(err, ErrNoRows) {
		return nil, apperr.NotFound("Комментарий не найден")
	}
	if err != nil {
		return nil, err
	}
	if comment.UserID != actor.ID {
		return nil, apperr.Forbidden("Можно редактировать только свой комментарий")
	}
	mentioned, err := s.resolveMentions(ctx, projectID, content)
	if err != nil {
		return nil, err
	}
	if err := s.store.UpdateCommentWithMentions(ctx, comment.ID, content, mentioned); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "UPDATE", EntityType: "comment", EntityID: &comment.ID})
	// TODO(phase2): ws broadcast (comment updated)
	comment.Content = content
	comment.Username = actor.Username
	comment.Mentions = mentioned
	return comment, nil
}

// DeleteComment — удаляет свой комментарий.
func (s *Service) DeleteComment(ctx context.Context, projectID, vulnID, commentID int32, actor Actor) error {
	if _, err := s.getVuln(ctx, projectID, vulnID); err != nil {
		return err
	}
	comment, err := s.store.GetVulnComment(ctx, commentID, vulnID)
	if errors.Is(err, ErrNoRows) {
		return apperr.NotFound("Комментарий не найден")
	}
	if err != nil {
		return err
	}
	if comment.UserID != actor.ID {
		return apperr.Forbidden("Можно удалить только свой комментарий")
	}
	if err := s.store.DeleteVulnComment(ctx, comment.ID); err != nil {
		return err
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "DELETE", EntityType: "comment", EntityID: &comment.ID})
	// TODO(phase2): ws broadcast (comment deleted)
	return nil
}

// resolveMentions — @упоминания → пользователи (участник проекта ИЛИ админ),
// включая самого автора (self получает строку comment_mentions, но не уведомление).
func (s *Service) resolveMentions(ctx context.Context, projectID int32, content string) ([]Mention, error) {
	usernames := extractMentions(content)
	if len(usernames) == 0 {
		return nil, nil
	}
	return s.store.ResolveCommentMentionUsers(ctx, projectID, usernames)
}

// ─────────────────────────── files ───────────────────────────

// ListFiles — файлы уязвимости.
func (s *Service) ListFiles(ctx context.Context, projectID, vulnID int32) ([]File, error) {
	if _, err := s.getVuln(ctx, projectID, vulnID); err != nil {
		return nil, err
	}
	return s.store.ListVulnFiles(ctx, vulnID)
}

// UploadFile — загружает файл доказательной базы. Размер ≤ 50 МБ; MIME определяется
// по байтам содержимого и ограничен allow-set.
func (s *Service) UploadFile(ctx context.Context, projectID, vulnID int32, filename string, data []byte, actor Actor) (*File, error) {
	if _, err := s.getVuln(ctx, projectID, vulnID); err != nil {
		return nil, err
	}
	if int64(len(data)) > maxFileSize {
		return nil, apperr.Validation("Размер файла превышает 50 МБ")
	}
	mime := sniffContentType(data)
	if !allowedMIME[mime] {
		return nil, apperr.Validation("Неподдерживаемый тип файла")
	}
	safeName := sanitizeFilename(filename, "file.bin")
	key := uuid.NewString() + "-" + safeName
	if err := s.storage.Put(ctx, key, data, mime); err != nil {
		return nil, err
	}
	file, err := s.store.InsertFile(ctx, NewFile{
		VulnerabilityID: vulnID, OriginalName: safeName, ContentType: mime,
		SizeBytes: int64(len(data)), MinioBucket: s.bucket, MinioKey: key, UploadedBy: actor.ID,
	})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "FILE_UPLOAD", EntityType: "file", EntityID: &file.ID})
	// TODO(phase2): ws broadcast (file created)
	return file, nil
}

// Download — бинарный контент файла с собственной проверкой доступа (эндпоинт
// без project_id): админ проходит, иначе нужно членство в проекте уязвимости.
func (s *Service) Download(ctx context.Context, fileID int32, actor Actor) (*File, []byte, error) {
	file, err := s.store.GetFileByID(ctx, fileID)
	if errors.Is(err, ErrNoRows) {
		return nil, nil, apperr.NotFound("Файл не найден")
	}
	if err != nil {
		return nil, nil, err
	}
	projectID, err := s.store.VulnProjectID(ctx, file.VulnerabilityID)
	if errors.Is(err, ErrNoRows) {
		return nil, nil, apperr.NotFound("Уязвимость не найдена")
	}
	if err != nil {
		return nil, nil, err
	}
	if !actor.IsAdmin() {
		member, err := s.store.IsProjectMember(ctx, projectID, actor.ID)
		if err != nil {
			return nil, nil, err
		}
		if !member {
			return nil, nil, apperr.Forbidden("Нет доступа к файлу")
		}
	}
	data, _, err := s.storage.Get(ctx, file.MinioKey)
	if err != nil {
		return nil, nil, err
	}
	return file, data, nil
}

// DeleteFile — удаляет файл уязвимости (метаданные + объект в хранилище).
func (s *Service) DeleteFile(ctx context.Context, projectID, vulnID, fileID int32, actor Actor) error {
	if _, err := s.getVuln(ctx, projectID, vulnID); err != nil {
		return err
	}
	file, err := s.store.GetFileForVuln(ctx, fileID, vulnID)
	if errors.Is(err, ErrNoRows) {
		return apperr.NotFound("Файл не найден")
	}
	if err != nil {
		return err
	}
	if err := s.store.DeleteFile(ctx, file.ID); err != nil {
		return err
	}
	_ = s.storage.Delete(ctx, file.MinioKey) // best-effort (как в Python — после commit)
	s.audit(ctx, AuditEntry{UserID: &actor.ID, Action: "FILE_DELETE", EntityType: "file", EntityID: &fileID})
	// TODO(phase2): ws broadcast (file deleted)
	return nil
}

// ─────────────────────────── workflow steps ───────────────────────────

// stepMarkerRe — «1.» / «2)» / «-» / «•» в начале строки (порт _STEP_MARKER_RE).
var stepMarkerRe = regexp.MustCompile(`^\s*(?:\d+[.)]|[-*•])\s*`)

// splitStepsText — порт _split_steps_text.
func splitStepsText(text string) []string {
	text = strings.ReplaceAll(text, "\r", "")
	var steps []string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		stripped := strings.TrimSpace(stepMarkerRe.ReplaceAllString(line, ""))
		if stripped == "" {
			continue
		}
		if len(steps) > 0 && stripped == line {
			steps[len(steps)-1] = steps[len(steps)-1] + "\n" + stripped
		} else {
			steps = append(steps, stripped)
		}
	}
	return steps
}

// hydrateWorkflowSteps — порт _hydrate_workflow_steps: если JSON есть — разбираем,
// иначе строим из текста steps_to_reproduce.
func hydrateWorkflowSteps(v *Vuln) {
	if len(v.WorkflowStepsRaw) > 0 && string(bytes.TrimSpace(v.WorkflowStepsRaw)) != "null" {
		var steps []WorkflowStep
		if err := json.Unmarshal(v.WorkflowStepsRaw, &steps); err == nil {
			v.WorkflowSteps = steps
			return
		}
	}
	text := ""
	if v.StepsToReproduce != nil {
		text = *v.StepsToReproduce
	}
	steps := []WorkflowStep{}
	for _, d := range splitStepsText(text) {
		desc := d
		steps = append(steps, WorkflowStep{ID: uuid.NewString(), Description: &desc, ImageFileIDs: []int32{}})
	}
	v.WorkflowSteps = steps
}

// normalizeWorkflowSteps — порт _normalize_workflow_steps.
func normalizeWorkflowSteps(steps []WorkflowStep) []WorkflowStep {
	out := []WorkflowStep{}
	for _, raw := range steps {
		desc := ""
		if raw.Description != nil {
			desc = strings.TrimSpace(*raw.Description)
		}
		reqRaw := ""
		if raw.EndpointRequestRaw != nil {
			reqRaw = strings.TrimSpace(*raw.EndpointRequestRaw)
		}
		var endpointID *int32
		if raw.EndpointID != nil && *raw.EndpointID != 0 {
			endpointID = raw.EndpointID
		}
		imgs := []int32{}
		for _, id := range raw.ImageFileIDs {
			if id != 0 {
				imgs = append(imgs, id)
			}
		}
		if desc == "" && len(imgs) == 0 && endpointID == nil && reqRaw == "" {
			continue
		}
		var descPtr *string
		if desc != "" {
			descPtr = &desc
		}
		var reqPtr *string
		if reqRaw != "" {
			reqPtr = &reqRaw
		}
		id := raw.ID
		if id == "" {
			id = uuid.NewString()
		}
		out = append(out, WorkflowStep{
			ID: id, Description: descPtr, ImageFileIDs: imgs, EndpointID: endpointID, EndpointRequestRaw: reqPtr,
		})
	}
	return out
}

// workflowStepsToText — порт _workflow_steps_to_text.
func workflowStepsToText(steps []WorkflowStep) *string {
	if len(steps) == 0 {
		return nil
	}
	blocks := make([]string, 0, len(steps))
	for i, step := range steps {
		idx := i + 1
		desc := ""
		if step.Description != nil {
			desc = strings.TrimSpace(*step.Description)
		}
		block := fmt.Sprintf("%d. Этап %d", idx, idx)
		if desc != "" {
			block += "\n" + desc
		}
		if step.EndpointID != nil || (step.EndpointRequestRaw != nil && *step.EndpointRequestRaw != "") {
			block += "\n[Endpoint: привязан]"
		}
		if len(step.ImageFileIDs) > 0 {
			block += fmt.Sprintf("\n[Изображений: %d]", len(step.ImageFileIDs))
		}
		blocks = append(blocks, block)
	}
	text := strings.Join(blocks, "\n\n")
	return &text
}

// validateWorkflowStepImages — порт _validate_workflow_step_images. Все image_file_ids
// должны принадлежать этой уязвимости. Точный список отсутствующих недоступен
// (есть только count-запрос) — в ошибке перечисляем запрошенные id.
func (s *Service) validateWorkflowStepImages(ctx context.Context, vulnID *int32, steps []WorkflowStep) error {
	idSet := map[int32]bool{}
	for _, st := range steps {
		for _, id := range st.ImageFileIDs {
			if id != 0 {
				idSet[id] = true
			}
		}
	}
	if len(idSet) == 0 {
		return nil
	}
	if vulnID == nil {
		return apperr.Validation("Нельзя указывать image_file_ids до загрузки файлов уязвимости")
	}
	ids := make([]int32, 0, len(idSet))
	for id := range idSet {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	count, err := s.store.CountFileImagesForVuln(ctx, *vulnID, ids)
	if err != nil {
		return err
	}
	if int(count) != len(ids) {
		strs := make([]string, len(ids))
		for i, id := range ids {
			strs[i] = strconv.Itoa(int(id))
		}
		return apperr.Validation("workflow_steps.image_file_ids содержат файлы, не принадлежащие уязвимости: " + strings.Join(strs, ", "))
	}
	return nil
}

// ─────────────────────────── helpers ───────────────────────────

func (s *Service) audit(ctx context.Context, e AuditEntry) {
	_ = s.store.InsertAudit(ctx, e)
}

// extractMentions — уникальные username из @упоминаний (порт set(MENTION_RE.findall)).
func extractMentions(content string) []string {
	matches := mentionRe.FindAllStringSubmatch(content, -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// mapEnumFilter — «» → без фильтра; иначе upper и проверка по множеству. Неизвестное
// значение → (без результата), как сравнение по несуществующему enum в Python.
func mapEnumFilter(raw string, valid map[string]bool) (value string, ok bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", true
	}
	up := strings.ToUpper(raw)
	if !valid[up] {
		return "", false
	}
	return up, true
}

// sniffContentType — определяет MIME по байтам (net/http.DetectContentType + ручные
// проверки webp/gzip/tar/xml/json), приводя к значениям из allow-set.
func sniffContentType(data []byte) string {
	if len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP" {
		return "image/webp"
	}
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		return "application/gzip"
	}
	if len(data) >= 262 && string(data[257:262]) == "ustar" {
		return "application/x-tar"
	}
	ct := http.DetectContentType(data)
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch ct {
	case "application/x-gzip":
		return "application/gzip"
	case "text/xml":
		return "application/xml"
	}
	if ct == "text/plain" {
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(trimmed) {
			return "application/json"
		}
		if bytes.HasPrefix(trimmed, []byte("<?xml")) {
			return "application/xml"
		}
	}
	return ct
}

// sanitizeFilename — порт _sanitize_filename: без path-separators, null-байтов и
// непечатаемых символов; ведущие точки срезаются.
func sanitizeFilename(raw, fallback string) string {
	if raw == "" {
		return fallback
	}
	name := strings.ReplaceAll(raw, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, ch := range name {
		if ch == 0 {
			continue
		}
		if unicode.IsPrint(ch) {
			b.WriteRune(ch)
		}
	}
	name = strings.TrimLeft(b.String(), ".")
	if name == "" {
		return fallback
	}
	return name
}

func toWorkflowSteps(v any) []WorkflowStep {
	if steps, ok := v.([]WorkflowStep); ok {
		return steps
	}
	return nil
}

func mustMarshalSteps(steps []WorkflowStep) []byte {
	if steps == nil {
		steps = []WorkflowStep{}
	}
	b, err := json.Marshal(steps)
	if err != nil {
		return []byte("[]")
	}
	return b
}

func asFloatPtr(v any) *float64 {
	switch f := v.(type) {
	case float64:
		return &f
	case float32:
		x := float64(f)
		return &x
	default:
		return nil
	}
}

func strVal(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// strOrNil — *string → any (nil, если nil) для хранения в payload.
func strOrNil(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func toInt32(v any) int32 {
	switch n := v.(type) {
	case int32:
		return n
	case int:
		return int32(n)
	case int64:
		return int32(n)
	case float64:
		return int32(n)
	default:
		return 0
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
