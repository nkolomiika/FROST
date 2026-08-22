package integrations

import (
	"context"
	"errors"
	"strings"

	"github.com/nkolomiika/frost/internal/apperr"
)

// Service — use-cases интеграций. Зависит только от портов Store + Cipher.
type Service struct {
	store  Store
	cipher Cipher
}

// NewService собирает сервис интеграций.
func NewService(store Store, cipher Cipher) *Service {
	return &Service{store: store, cipher: cipher}
}

// List возвращает ПОЛНЫЙ набор известных ключей: для каждого — установлен ли он
// (configured) и когда обновлён. Секреты не читаются и не отдаются.
func (s *Service) List(ctx context.Context) ([]Item, error) {
	metas, err := s.store.ListMeta(ctx)
	if err != nil {
		return nil, err
	}
	byName := make(map[string]StoredMeta, len(metas))
	for _, m := range metas {
		byName[m.KeyName] = m
	}
	items := make([]Item, 0, len(KnownKeys))
	for _, key := range KnownKeys {
		it := Item{KeyName: key}
		if m, ok := byName[key]; ok {
			it.Configured = true
			t := m.UpdatedAt
			it.UpdatedAt = &t
		}
		items = append(items, it)
	}
	return items, nil
}

// Set upsert'ит значение ключа (шифруя). Пустое значение УДАЛЯЕТ ключ. Возвращает
// обновлённый Item (configured bool). Имя ключа обязано быть известным.
func (s *Service) Set(ctx context.Context, keyName, value string, updatedBy int32) (Item, error) {
	keyName = strings.TrimSpace(keyName)
	if !IsKnownKey(keyName) {
		return Item{}, apperr.Validation("Неизвестный ключ интеграции: " + keyName)
	}
	if strings.TrimSpace(value) == "" {
		// Пустое значение = удалить ключ.
		if err := s.store.Delete(ctx, keyName); err != nil {
			return Item{}, err
		}
		return Item{KeyName: keyName, Configured: false}, nil
	}
	enc, err := s.cipher.Encrypt(value)
	if err != nil {
		return Item{}, err
	}
	by := updatedBy
	var byPtr *int32
	if by != 0 {
		byPtr = &by
	}
	if err := s.store.Upsert(ctx, keyName, []byte(enc), byPtr); err != nil {
		return Item{}, err
	}
	return Item{KeyName: keyName, Configured: true}, nil
}

// GetIntegrationKey возвращает расшифрованное значение ключа для внутренних нужд
// (сканы). ok=false — ключ не задан (не ошибка). Используется, например,
// github-сканом для получения github_token.
func (s *Service) GetIntegrationKey(ctx context.Context, keyName string) (string, bool, error) {
	enc, err := s.store.GetEncrypted(ctx, keyName)
	if errors.Is(err, ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	plain, err := s.cipher.Decrypt(string(enc))
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}
