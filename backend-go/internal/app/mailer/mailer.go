// Package mailer — обработка mail-outbox (порт worker/mail_worker.py process_mail_job).
// Воркер — DB-поллер: mail_jobs служит durable-очередью. Статус-машина:
// pending → processing → sent | (pending при attempts<max) | (failed при attempts>=max).
package mailer

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/nkolomiika/frost/internal/adapters/mail"
)

// Job — задание из mail_jobs, взятое в работу.
type Job struct {
	ID             int32
	RecipientEmail string
	Subject        string
	Template       string
	Payload        []byte // JSON
	Attempts       int32  // после инкремента при взятии в работу
}

// Store — порт хранилища mail-outbox.
type Store interface {
	// ClaimPending возвращает кандидатов (pending или failed с attempts<max).
	ClaimPending(ctx context.Context, limit, maxAttempts int32) ([]int32, error)
	// MarkProcessing атомарно берёт задание в работу (status='processing', attempts++)
	// при status<>'sent'. Возвращает (nil,nil), если уже отправлено/недоступно.
	MarkProcessing(ctx context.Context, id int32) (*Job, error)
	MarkSent(ctx context.Context, id int32) error
	MarkPending(ctx context.Context, id int32, errMsg string) error
	MarkFailed(ctx context.Context, id int32, errMsg string) error
}

// Sender отправляет письмо (реализуется adapters/mail.Sender).
type Sender interface {
	Send(to, subject, text, htmlBody string) error
}

// Service — обработка mail-заданий.
type Service struct {
	store       Store
	sender      Sender
	maxAttempts int32
	log         *slog.Logger
}

// NewService собирает сервис почты.
func NewService(store Store, sender Sender, maxAttempts int32, log *slog.Logger) *Service {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: store, sender: sender, maxAttempts: maxAttempts, log: log}
}

// ProcessPending берёт пачку заданий и обрабатывает каждое.
func (s *Service) ProcessPending(ctx context.Context) error {
	ids, err := s.store.ClaimPending(ctx, 50, s.maxAttempts)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.ProcessOne(ctx, id); err != nil {
			s.log.Warn("mail job failed", "id", id, "err", err)
		}
	}
	return nil
}

// ProcessOne обрабатывает одно задание по id (идемпотентно относительно 'sent').
func (s *Service) ProcessOne(ctx context.Context, id int32) error {
	job, err := s.store.MarkProcessing(ctx, id)
	if err != nil {
		return err
	}
	if job == nil {
		return nil // уже отправлено/взято — пропускаем
	}
	var payload map[string]any
	if len(job.Payload) > 0 {
		_ = json.Unmarshal(job.Payload, &payload)
	}
	rendered, err := mail.Render(job.Template, payload)
	if err != nil {
		return s.fail(ctx, job, err)
	}
	if err := s.sender.Send(job.RecipientEmail, job.Subject, rendered.Text, rendered.HTML); err != nil {
		return s.fail(ctx, job, err)
	}
	return s.store.MarkSent(ctx, job.ID)
}

// fail помечает задание pending (для ретрая) или failed (при исчерпании попыток).
func (s *Service) fail(ctx context.Context, job *Job, cause error) error {
	msg := cause.Error()
	if len(msg) > 2000 {
		msg = msg[:2000]
	}
	if job.Attempts >= s.maxAttempts {
		return s.store.MarkFailed(ctx, job.ID, msg)
	}
	return s.store.MarkPending(ctx, job.ID, msg)
}
