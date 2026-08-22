// Package leaksink — адаптер, соединяющий сканеры рекона (порт recon.LeakSink) с
// единым хранилищем утечек (leaks.Service). Преобразует source-agnostic
// recon.LeakRecord в leaks.LeakInput и пишет через RecordLeaks. Так recon не
// зависит от контекста leaks напрямую (инверсия зависимости в composition root).
package leaksink

import (
	"context"
	"encoding/json"

	"github.com/nkolomiika/frost/internal/app/leaks"
	"github.com/nkolomiika/frost/internal/app/recon"
)

// Sink реализует recon.LeakSink поверх leaks.Service.
type Sink struct {
	svc *leaks.Service
}

// New создаёт приёмник поверх сервиса утечек.
func New(svc *leaks.Service) *Sink { return &Sink{svc: svc} }

var _ recon.LeakSink = (*Sink)(nil)

// WriteLeaks преобразует находки сканера в записи хранилища и сохраняет их.
func (s *Sink) WriteLeaks(ctx context.Context, projectID int32, jobID *int32, recs []recon.LeakRecord) error {
	rows := make([]leaks.LeakInput, 0, len(recs))
	for _, r := range recs {
		var detail []byte
		if len(r.Detail) > 0 {
			detail, _ = json.Marshal(r.Detail)
		}
		rows = append(rows, leaks.LeakInput{
			ProjectID: projectID,
			JobID:     jobID,
			Source:    r.Source,
			Kind:      r.Kind,
			Subject:   nonEmpty(r.Subject),
			Value:     nonEmpty(r.Value),
			Detail:    detail,
			Verified:  r.Verified,
		})
	}
	return s.svc.RecordLeaks(ctx, rows)
}

// nonEmpty возвращает *string или nil для пустой строки.
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
