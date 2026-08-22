package leaks

import (
	"context"
	"fmt"
	"strings"
)

// Service — use-cases утечек. Зависит только от порта Store.
type Service struct {
	store Store
}

// NewService собирает сервис утечек.
func NewService(store Store) *Service {
	return &Service{store: store}
}

// RecordLeaks складывает находки сканера в карантин проекта. Реализует запись для
// ЛЮБОГО источника (github/linkedin/…). Пустой вход — no-op.
func (s *Service) RecordLeaks(ctx context.Context, rows []LeakInput) error {
	if len(rows) == 0 {
		return nil
	}
	return s.store.InsertLeaks(ctx, rows)
}

// Report собирает отчёт утечек проекта (все источники или отфильтрованные по
// source/job_id) с агрегатами total/verified/imported/by_source.
func (s *Service) Report(ctx context.Context, projectID int32, f Filter) (Report, error) {
	rep := Report{Source: f.Source, JobID: f.JobID, Leaks: []Leak{}, Summary: Summary{BySource: map[string]int{}}}
	rows, err := s.store.ListLeaks(ctx, projectID, f)
	if err != nil {
		return Report{}, err
	}
	if rows != nil {
		rep.Leaks = rows
	}
	for _, l := range rep.Leaks {
		rep.Summary.Total++
		if l.Verified {
			rep.Summary.Verified++
		}
		if l.Imported {
			rep.Summary.Imported++
		}
		rep.Summary.BySource[l.Source]++
	}
	return rep, nil
}

// Import создаёт реальные записи проекта (project_notes) из выбранных утечек и
// помечает их imported. Идемпотентно: уже импортированные пропускаются.
func (s *Service) Import(ctx context.Context, projectID, actorID int32, ids []int32) (ImportResult, error) {
	if len(ids) == 0 {
		return ImportResult{}, nil
	}
	rows, err := s.store.ListLeaksByIDs(ctx, projectID, ids)
	if err != nil {
		return ImportResult{}, err
	}
	imported := make([]int32, 0, len(rows))
	for _, l := range rows {
		if l.Imported {
			continue
		}
		title, content := noteFromLeak(l)
		if err := s.store.ImportLeakNote(ctx, projectID, title, content, actorID); err != nil {
			return ImportResult{}, err
		}
		imported = append(imported, l.ID)
	}
	if len(imported) > 0 {
		if err := s.store.MarkImported(ctx, projectID, imported); err != nil {
			return ImportResult{}, err
		}
	}
	return ImportResult{Imported: len(imported)}, nil
}

// Clear чистит утечки проекта (с фильтрами source/job_id). Возвращает число удалённых.
func (s *Service) Clear(ctx context.Context, projectID int32, f Filter) (int64, error) {
	return s.store.ClearLeaks(ctx, projectID, f)
}

// noteFromLeak строит заголовок (уникален — id утечки) и markdown-содержимое
// страницы-заметки импорта.
func noteFromLeak(l Leak) (string, string) {
	subject := ""
	if l.Subject != nil {
		subject = *l.Subject
	}
	title := fmt.Sprintf("Leak #%d — %s/%s", l.ID, l.Source, orDash(subject))

	var b strings.Builder
	fmt.Fprintf(&b, "# Leak (%s / %s)\n\n", l.Source, l.Kind)
	if subject != "" {
		fmt.Fprintf(&b, "- **Subject:** %s\n", subject)
	}
	if l.Value != nil && *l.Value != "" {
		fmt.Fprintf(&b, "- **Value:** `%s`\n", *l.Value)
	}
	fmt.Fprintf(&b, "- **Verified:** %t\n", l.Verified)
	if len(l.Detail) > 0 {
		fmt.Fprintf(&b, "\n```json\n%s\n```\n", string(l.Detail))
	}
	return title, b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
