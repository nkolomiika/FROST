package wordlists

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/google/uuid"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"github.com/nkolomiika/frost/internal/apperr"
)

// ErrNoRows — словарь не найден в хранилище метаданных.
var ErrNoRows = errors.New("no rows")

// Service — use-cases словарей: загрузка (валидация + MinIO + метаданные), список
// (бандл-тиры + кастомные), удаление (объект MinIO + строка) и материализация пути
// для запуска инструмента (dnsx/ffuf).
type Service struct {
	store   Store
	storage Storage
}

// NewService собирает сервис словарей.
func NewService(store Store, storage Storage) *Service {
	return &Service{store: store, storage: storage}
}

// Upload валидирует загруженные байты (размер ≤ 50 МБ, текст, не бинарь), кладёт их
// в MinIO под СЕРВЕРНЫМ ключом wordlists/{uuid} (имя файла пользователя — только
// ярлык name) и вставляет строку метаданных. Возвращает созданный Wordlist.
func (s *Service) Upload(ctx context.Context, name string, data []byte, uploadedBy *int32) (Wordlist, error) {
	lines, err := validateWordlistBytes(data)
	if err != nil {
		return Wordlist{}, err
	}
	name = sanitizeName(name)

	// Серверный ключ: имя файла пользователя НИКОГДА не участвует в пути — нет
	// path-traversal, нет коллизий ключей.
	key := objectKeyPrefix + uuid.NewString()
	if err := s.storage.Put(ctx, key, data, "text/plain; charset=utf-8"); err != nil {
		return Wordlist{}, err
	}

	size := int64(len(data))
	ln := int32(lines)
	wl, err := s.store.Insert(ctx, NewWordlist{
		Name: name, ObjectKey: key, SizeBytes: &size, Lines: &ln, UploadedBy: uploadedBy,
	})
	if err != nil {
		// Метаданные не записались — не оставляем осиротевший объект в MinIO.
		_ = s.storage.Delete(ctx, key)
		return Wordlist{}, err
	}
	return wl, nil
}

// List отдаёт ВСЕ забандленные на диске словари (рекурсивный обход WordlistDir:
// SecLists + n0kovo, по оригинальным именам) + кастомные словари workspace.
// Bundled собирается из реальных файлов, а не из фиксированных тиров.
func (s *Service) List(ctx context.Context) (Listing, error) {
	custom, err := s.store.List(ctx)
	if err != nil {
		return Listing{}, err
	}
	files, err := reconnet.EnumerateWordlists()
	if err != nil {
		return Listing{}, err
	}
	bundled := make([]BundledWordlist, 0, len(files))
	for _, f := range files {
		bundled = append(bundled, BundledWordlist{
			Name: f.Name, Path: f.Path, Category: f.Category, Lines: f.Lines,
		})
	}
	return Listing{Bundled: bundled, Custom: custom}, nil
}

// Delete удаляет объект MinIO и строку метаданных. Нет строки → 404. Ошибку удаления
// объекта не глушим (осиротевшая строка хуже осиротевшего объекта).
func (s *Service) Delete(ctx context.Context, id int32) error {
	wl, err := s.store.Get(ctx, id)
	if errors.Is(err, ErrNoRows) {
		return apperr.NotFound("Словарь не найден")
	}
	if err != nil {
		return err
	}
	if err := s.storage.Delete(ctx, wl.ObjectKey); err != nil {
		return err
	}
	if _, err := s.store.Delete(ctx, id); err != nil {
		return err
	}
	return nil
}

// Materialize — ЕДИНСТВЕННЫЙ путь, отдающий имя файла-словаря инструменту фермы.
// Порядок разрешения: customID>0 (кастомный из MinIO во ВРЕМЕННЫЙ серверный файл) →
// bundledPath!="" (забандленный на диске файл по ОТНОСИТЕЛЬНОМУ пути, ВАЛИДИРУЕТСЯ
// под WordlistDir и возвращается напрямую, cleanup — no-op) → tier (бандл-тир по
// WordlistSize). Путь забандленного словаря приходит как пользовательский выбор, но
// ResolveWordlistPath синтаксически чистит его и требует, чтобы он оставался под
// WordlistDir → traversal наружу невозможен; невалидный путь → ошибка (наверх
// деградирует к тиру в resolveWordlist). Пользовательская строка НИКОГДА не уходит
// инструменту без серверной валидации.
func (s *Service) Materialize(ctx context.Context, customID int, bundledPath, tier string) (path string, cleanup func(), err error) {
	noop := func() {}
	if customID <= 0 {
		if bundledPath != "" {
			abs, ok := reconnet.ResolveWordlistPath(bundledPath)
			if !ok {
				return "", noop, apperr.Validation("Недопустимый путь словаря")
			}
			return abs, noop, nil
		}
		return reconnet.WordlistPath(tier), noop, nil
	}
	wl, err := s.store.Get(ctx, int32(customID))
	if errors.Is(err, ErrNoRows) {
		return "", noop, apperr.NotFound("Словарь не найден")
	}
	if err != nil {
		return "", noop, err
	}
	data, _, err := s.storage.Get(ctx, wl.ObjectKey)
	if err != nil {
		return "", noop, err
	}
	f, err := os.CreateTemp("", "frost-wordlist-*.txt")
	if err != nil {
		return "", noop, err
	}
	tmp := f.Name()
	if _, err := io.Copy(f, bytes.NewReader(data)); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", noop, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", noop, err
	}
	return tmp, func() { _ = os.Remove(tmp) }, nil
}

// validateWordlistBytes проверяет, что загруженное похоже на текстовый словарь:
// непустое, ≤ MaxUploadBytes, без NUL-байтов (бинарь). Возвращает число непустых
// строк.
func validateWordlistBytes(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, apperr.Validation("Пустой файл словаря")
	}
	if int64(len(data)) > MaxUploadBytes {
		return 0, apperr.Validation("Файл словаря слишком большой (максимум 50 МБ)")
	}
	if bytes.IndexByte(data, 0x00) >= 0 {
		return 0, apperr.Validation("Файл словаря выглядит бинарным (найден NUL-байт)")
	}
	lines := 0
	for _, ln := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(ln)) > 0 {
			lines++
		}
	}
	if lines == 0 {
		return 0, apperr.Validation("В файле словаря нет ни одной непустой строки")
	}
	return lines, nil
}

// sanitizeName нормализует ярлык словаря: обрезает пробелы, дефолт для пустого,
// ограничивает длину. Это только display-label — в путь MinIO он не идёт.
func sanitizeName(name string) string {
	name = string(bytes.TrimSpace([]byte(name)))
	if name == "" {
		return "wordlist.txt"
	}
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}
