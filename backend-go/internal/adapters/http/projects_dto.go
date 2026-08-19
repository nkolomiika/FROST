package http

import (
	"encoding/json"
	"strings"
	"time"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/nkolomiika/frost/internal/adapters/http/apiv1"
	"github.com/nkolomiika/frost/internal/app/projects"
)

// ─────────────────────────── date / ptr helpers ───────────────────────────

// fromAPIDate: *openapi_types.Date → *time.Time.
func fromAPIDate(d *openapi_types.Date) *time.Time {
	if d == nil {
		return nil
	}
	t := d.Time
	return &t
}

// toAPIDate: *time.Time → *openapi_types.Date.
func toAPIDate(t *time.Time) *openapi_types.Date {
	if t == nil {
		return nil
	}
	return &openapi_types.Date{Time: *t}
}

// intPtr32: *int → *int32.
func intPtr32(p *int) *int32 {
	if p == nil {
		return nil
	}
	v := int32(*p)
	return &v
}

// int32Ptr: *int32 → *int.
func int32Ptr(p *int32) *int {
	if p == nil {
		return nil
	}
	v := int(*p)
	return &v
}

// isoTime: *time.Time → *string (RFC3339, как isoformat в Python) или nil.
func isoTime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

// rawOrNil: json.RawMessage → any (nil, если пусто) для вложения в map-ответ.
func rawOrNil(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}

// ─────────────────────────── DTO mappers ───────────────────────────

func projectOut(p *projects.Project) apiv1.ProjectOut {
	return apiv1.ProjectOut{
		Id:               int(p.ID),
		Name:             p.Name,
		Folder:           p.Folder,
		Description:      p.Description,
		StartDate:        toAPIDate(p.StartDate),
		EndDate:          toAPIDate(p.EndDate),
		TimelineFrozenAt: p.TimelineFrozenAt,
		Status:           apiv1.ProjectStatus(strings.ToLower(p.Status)),
		CreatedBy:        int(p.CreatedBy),
		CreatedAt:        p.CreatedAt,
		UpdatedAt:        p.UpdatedAt,
	}
}

func folderOut(f *projects.Folder) apiv1.ProjectFolderOut {
	return apiv1.ProjectFolderOut{
		Id:        int(f.ID),
		Name:      f.Name,
		Path:      f.Path,
		ParentId:  int32Ptr(f.ParentID),
		CreatedBy: int(f.CreatedBy),
		CreatedAt: f.CreatedAt,
		UpdatedAt: f.UpdatedAt,
	}
}

func noteOut(n *projects.Note) apiv1.ProjectNoteOut {
	return apiv1.ProjectNoteOut{
		Id:                int(n.ID),
		ProjectId:         int(n.ProjectID),
		ParentId:          int32Ptr(n.ParentID),
		Title:             n.Title,
		Content:           n.Content,
		SortOrder:         int(n.SortOrder),
		CreatedBy:         int(n.CreatedBy),
		UpdatedBy:         int32Ptr(n.UpdatedBy),
		CreatedByUsername: n.CreatedByUsername,
		CreatedAt:         n.CreatedAt,
		UpdatedAt:         n.UpdatedAt,
	}
}

func notesOut(notes []projects.Note) []apiv1.ProjectNoteOut {
	out := make([]apiv1.ProjectNoteOut, 0, len(notes))
	for i := range notes {
		out = append(out, noteOut(&notes[i]))
	}
	return out
}

func noteCommentOut(c *projects.NoteComment) apiv1.ProjectNoteCommentOut {
	return apiv1.ProjectNoteCommentOut{
		Id:        int(c.ID),
		ProjectId: int(c.ProjectID),
		NoteId:    int(c.NoteID),
		UserId:    int(c.UserID),
		Username:  c.Username,
		AvatarUrl: c.AvatarURL,
		Content:   c.Content,
		CreatedAt: c.CreatedAt,
		UpdatedAt: c.UpdatedAt,
	}
}

func credentialOut(c *projects.Credential) apiv1.ProjectCredentialOut {
	return apiv1.ProjectCredentialOut{
		Id:                int(c.ID),
		ProjectId:         int(c.ProjectID),
		Username:          c.Username,
		Password:          c.Password,
		Host:              c.Host,
		CreatedBy:         int(c.CreatedBy),
		CreatedByUsername: c.CreatedByUsername,
		CreatedAt:         c.CreatedAt,
		UpdatedAt:         c.UpdatedAt,
	}
}
