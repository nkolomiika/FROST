package recon

import (
	"context"
	"strconv"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
)

// WordlistMaterializer — порт материализации словаря в СЕРВЕРНЫЙ путь для запуска
// инструмента (dnsx -w / ffuf -w). Реализует wordlists.Service (composition root).
// Порядок: customID>0 → кастомный из MinIO во temp; bundledPath!="" → забандленный
// файл на диске (валидируется под WordlistDir); иначе — бандл-тир по tier. cleanup
// ВСЕГДА безопасно вызвать (для бандла/пути — no-op). Это ЕДИНСТВЕННЫЙ путь, отдающий
// имя файла-словаря бинарю — сырые пользовательские строки сюда не попадают.
type WordlistMaterializer interface {
	Materialize(ctx context.Context, customID int, bundledPath, tier string) (path string, cleanup func(), err error)
}

// AttachWordlists подключает материализатор словарей (composition root). Без него
// брут/ffuf падают на бандл-тиры (fallback в resolveWordlist). Отдельный сеттер —
// чтобы не ломать сигнатуру NewService и её тестовых вызовов.
func (s *Service) AttachWordlists(m WordlistMaterializer) { s.wordlists = m }

// resolveWordlist материализует словарь для инструмента: при подключённом
// материализаторе делегирует ему (кастомный id → temp, путь → забандленный файл,
// иначе → бандл-тир); без него или при ошибке — молча деградирует к бандл-пути тира
// (cleanup — no-op). Возвращает путь, cleanup (всегда не-nil) и мягкую ошибку-метку
// (для result.Errors), если выбранный словарь не удалось материализовать.
func (s *Service) resolveWordlist(ctx context.Context, customID int, bundledPath, tier string) (string, func(), string) {
	noop := func() {}
	if s.wordlists == nil {
		return reconnet.WordlistPath(tier), noop, ""
	}
	path, cleanup, err := s.wordlists.Materialize(ctx, customID, bundledPath, tier)
	if err != nil {
		// Выбранный словарь недоступен → деградируем к бандл-тиру, прогон не валим.
		sel := "#" + strconv.Itoa(customID)
		if customID <= 0 && bundledPath != "" {
			sel = "'" + bundledPath + "'"
		}
		return reconnet.WordlistPath(tier), noop, "словарь " + sel + " недоступен, использован бандл-тир '" + tier + "': " + err.Error()
	}
	if cleanup == nil {
		cleanup = noop
	}
	return path, cleanup, ""
}
