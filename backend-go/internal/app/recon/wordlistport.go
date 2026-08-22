package recon

import (
	"context"
	"strconv"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// WordlistMaterializer — порт материализации словаря в СЕРВЕРНЫЙ путь для запуска
// инструмента (dnsx -w / ffuf -w). Реализует wordlists.Service (composition root).
// customID==0 → бандл-тир по tier; customID>0 → кастомный словарь из MinIO во temp.
// cleanup ВСЕГДА безопасно вызвать (для бандла — no-op). Это ЕДИНСТВЕННЫЙ путь,
// отдающий имя файла-словаря бинарю — пользовательские имена файлов сюда не попадают.
type WordlistMaterializer interface {
	Materialize(ctx context.Context, customID int, tier string) (path string, cleanup func(), err error)
}

// AttachWordlists подключает материализатор словарей (composition root). Без него
// брут/ffuf падают на бандл-тиры (fallback в resolveWordlist). Отдельный сеттер —
// чтобы не ломать сигнатуру NewService и её тестовых вызовов.
func (s *Service) AttachWordlists(m WordlistMaterializer) { s.wordlists = m }

// resolveWordlist материализует словарь для инструмента: при подключённом
// материализаторе делегирует ему (кастомный id → temp, 0 → бандл-тир); без него или
// при ошибке — молча деградирует к бандл-пути тира (cleanup — no-op). Возвращает
// путь, cleanup (всегда не-nil) и мягкую ошибку-метку (для result.Errors), если
// кастомный словарь не удалось материализовать.
func (s *Service) resolveWordlist(ctx context.Context, customID int, tier string) (string, func(), string) {
	noop := func() {}
	if s.wordlists == nil {
		return reconnet.WordlistPath(tier), noop, ""
	}
	path, cleanup, err := s.wordlists.Materialize(ctx, customID, tier)
	if err != nil {
		// Кастомный словарь недоступен → деградируем к бандл-тиру, прогон не валим.
		return reconnet.WordlistPath(tier), noop, "словарь #" + strconv.Itoa(customID) + " недоступен, использован бандл-тир '" + tier + "': " + err.Error()
	}
	if cleanup == nil {
		cleanup = noop
	}
	return path, cleanup, ""
}
