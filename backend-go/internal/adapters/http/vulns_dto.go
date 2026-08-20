package http

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/vulns"
	"github.com/nkolomiika/frost/internal/apperr"
)

// ─────────────────────────── any/ptr helpers ───────────────────────────

func strAny(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func f32Any(p *float32) any {
	if p == nil {
		return nil
	}
	return float64(*p)
}

func cvssVerAny(p *apiv1.CvssVersion) any {
	if p == nil {
		return nil
	}
	return string(*p)
}

func f64ToF32Ptr(p *float64) *float32 {
	if p == nil {
		return nil
	}
	v := float32(*p)
	return &v
}

func cvssVersionOut(p *string) *apiv1.CvssVersion {
	if p == nil {
		return nil
	}
	v := apiv1.CvssVersion(*p)
	return &v
}

func int32SliceToIntPtr(ids []int32) *[]int {
	out := make([]int, 0, len(ids))
	for _, id := range ids {
		out = append(out, int(id))
	}
	return &out
}

func int32ToIntPtr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}

// ─────────────────────────── DTO in (payload builders) ───────────────────────────

// toDomainSteps: apiv1 workflow-шаги → доменные.
func toDomainSteps(steps *[]apiv1.VulnerabilityWorkflowStep) []vulns.WorkflowStep {
	out := []vulns.WorkflowStep{}
	if steps == nil {
		return out
	}
	for _, s := range *steps {
		ws := vulns.WorkflowStep{ID: s.Id, Description: s.Description, EndpointRequestRaw: s.EndpointRequestRaw}
		if s.EndpointId != nil {
			v := int32(*s.EndpointId)
			ws.EndpointID = &v
		}
		ws.ImageFileIDs = []int32{}
		if s.ImageFileIds != nil {
			for _, id := range *s.ImageFileIds {
				ws.ImageFileIDs = append(ws.ImageFileIDs, int32(id))
			}
		}
		out = append(out, ws)
	}
	return out
}

// buildCreatePayload — payload как model_dump() (все ключи присутствуют, значение
// None → nil). severity/status приводятся к БД-регистру (UPPERCASE).
func buildCreatePayload(req apiv1.VulnerabilityCreate) map[string]any {
	sev := vulns.SeverityInfo
	if req.Severity != nil {
		sev = strings.ToUpper(string(*req.Severity))
	}
	st := vulns.StatusOpen
	if req.Status != nil {
		st = strings.ToUpper(string(*req.Status))
	}
	return map[string]any{
		"host_id":            int32(req.HostId),
		"title":              req.Title,
		"description":        strAny(req.Description),
		"severity":           sev,
		"cvss_version":       cvssVerAny(req.CvssVersion),
		"cvss_score":         f32Any(req.CvssScore),
		"cvss_vector":        strAny(req.CvssVector),
		"cwe_id":             strAny(req.CweId),
		"status":             st,
		"workflow_steps":     toDomainSteps(req.WorkflowSteps),
		"steps_to_reproduce": strAny(req.StepsToReproduce),
		"impact":             strAny(req.Impact),
		"recommendations":    strAny(req.Recommendations),
	}
}

// buildUpdatePayload — payload как model_dump(exclude_unset=True): только присланные
// ключи присутствуют (JSON null → nil). severity/status → БД-регистр.
func buildUpdatePayload(body []byte) (map[string]any, error) {
	errBadBody := apperr.Validation("Некорректное тело запроса")
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, errBadBody
	}
	p := map[string]any{}
	isNull := func(b json.RawMessage) bool { return string(bytes.TrimSpace(b)) == "null" }

	setStr := func(key string, upper bool) error {
		v, ok := raw[key]
		if !ok {
			return nil
		}
		if isNull(v) {
			p[key] = nil
			return nil
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return errBadBody
		}
		if upper {
			s = strings.ToUpper(s)
		}
		p[key] = s
		return nil
	}

	for _, key := range []string{"title", "description", "cvss_vector", "cwe_id", "steps_to_reproduce", "impact", "recommendations", "cvss_version"} {
		if err := setStr(key, false); err != nil {
			return nil, err
		}
	}
	for _, key := range []string{"severity", "status"} {
		if err := setStr(key, true); err != nil {
			return nil, err
		}
	}
	if v, ok := raw["cvss_score"]; ok {
		if isNull(v) {
			p["cvss_score"] = nil
		} else {
			var f float64
			if err := json.Unmarshal(v, &f); err != nil {
				return nil, errBadBody
			}
			p["cvss_score"] = f
		}
	}
	if v, ok := raw["workflow_steps"]; ok {
		var steps []apiv1.VulnerabilityWorkflowStep
		if !isNull(v) {
			if err := json.Unmarshal(v, &steps); err != nil {
				return nil, errBadBody
			}
		}
		p["workflow_steps"] = toDomainSteps(&steps)
	}
	return p, nil
}

// ─────────────────────────── DTO out (mappers) ───────────────────────────

func workflowStepsOut(steps []vulns.WorkflowStep) *[]apiv1.VulnerabilityWorkflowStep {
	out := make([]apiv1.VulnerabilityWorkflowStep, 0, len(steps))
	for _, s := range steps {
		out = append(out, apiv1.VulnerabilityWorkflowStep{
			Id:                 s.ID,
			Description:        s.Description,
			ImageFileIds:       int32SliceToIntPtr(s.ImageFileIDs),
			EndpointId:         int32ToIntPtr(s.EndpointID),
			EndpointRequestRaw: s.EndpointRequestRaw,
		})
	}
	return &out
}

func vulnOut(v *vulns.Vuln) apiv1.VulnerabilityOut {
	return apiv1.VulnerabilityOut{
		Id:                int(v.ID),
		ProjectId:         int(v.ProjectID),
		Title:             v.Title,
		Description:       v.Description,
		Severity:          apiv1.Severity(strings.ToLower(v.Severity)),
		CvssVersion:       cvssVersionOut(v.CvssVersion),
		CvssScore:         f64ToF32Ptr(v.CvssScore),
		CvssVector:        v.CvssVector,
		CweId:             v.CweID,
		Status:            apiv1.VulnerabilityStatus(strings.ToLower(v.Status)),
		WorkflowSteps:     workflowStepsOut(v.WorkflowSteps),
		StepsToReproduce:  v.StepsToReproduce,
		Impact:            v.Impact,
		Recommendations:   v.Recommendations,
		CreatedBy:         int(v.CreatedBy),
		CreatedByUsername: v.CreatedByUsername,
		CreatedAt:         v.CreatedAt,
		UpdatedAt:         v.UpdatedAt,
	}
}

func vulnAssetOut(a vulns.AssetLink) apiv1.VulnerabilityAssetOut {
	return apiv1.VulnerabilityAssetOut{
		Id:              int(a.ID),
		VulnerabilityId: int(a.VulnerabilityID),
		AssetType:       apiv1.AssetType(strings.ToLower(a.AssetType)),
		AssetId:         int(a.AssetID),
	}
}

func vulnFileOut(f vulns.File) apiv1.FileOut {
	return apiv1.FileOut{
		Id:           int(f.ID),
		OriginalName: f.OriginalName,
		ContentType:  f.ContentType,
		SizeBytes:    int(f.SizeBytes),
		UploadedBy:   int(f.UploadedBy),
		UploadedAt:   f.UploadedAt,
	}
}

func vulnMentionsOut(mentions []vulns.Mention) []apiv1.MentionOut {
	out := make([]apiv1.MentionOut, 0, len(mentions))
	for _, m := range mentions {
		out = append(out, apiv1.MentionOut{UserId: int(m.UserID), Username: m.Username})
	}
	return out
}

// avatarURL — порт User.avatar_url (nil без аватара; версия по времени загрузки).
func avatarURL(userID int32, key *string, uploadedAt *time.Time) *string {
	if key == nil || *key == "" {
		return nil
	}
	var version int64
	if uploadedAt != nil {
		version = uploadedAt.Unix()
	}
	s := fmt.Sprintf("/api/v1/users/%d/avatar?v=%d", userID, version)
	return &s
}

func vulnCommentOut(c *vulns.Comment) apiv1.CommentOut {
	return apiv1.CommentOut{
		Id:              int(c.ID),
		VulnerabilityId: int(c.VulnerabilityID),
		UserId:          int(c.UserID),
		Username:        c.Username,
		AvatarUrl:       avatarURL(c.UserID, c.AvatarKey, c.AvatarUploadedAt),
		Content:         c.Content,
		Mentions:        vulnMentionsOut(c.Mentions),
		CreatedAt:       c.CreatedAt,
		UpdatedAt:       c.UpdatedAt,
	}
}

// vulnDetailOut — VulnerabilityOut + инъекция assets/files/comments_count в общий
// map-ответ (bespoke, без сгенерированного композита).
func vulnDetailOut(d *vulns.VulnDetail) map[string]any {
	b, _ := json.Marshal(vulnOut(d.Vuln))
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	assets := make([]apiv1.VulnerabilityAssetOut, 0, len(d.Assets))
	for _, a := range d.Assets {
		assets = append(assets, vulnAssetOut(a))
	}
	files := make([]apiv1.FileOut, 0, len(d.Files))
	for _, f := range d.Files {
		files = append(files, vulnFileOut(f))
	}
	m["assets"] = assets
	m["files"] = files
	m["comments_count"] = d.CommentsCount
	return m
}
