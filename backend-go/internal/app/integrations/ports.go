package integrations

import (
	"context"
	"errors"
)

// ErrNoRows — ключ не найден в хранилище.
var ErrNoRows = errors.New("no rows")

// Store — порт хранилища интеграций (реализует integrationsrepo поверх sqlc).
type Store interface {
	// GetEncrypted возвращает зашифрованное значение ключа. ErrNoRows — ключ не задан.
	GetEncrypted(ctx context.Context, keyName string) ([]byte, error)
	// ListMeta — метаданные всех заданных ключей (без значений).
	ListMeta(ctx context.Context) ([]StoredMeta, error)
	// Upsert вставляет/обновляет зашифрованное значение ключа.
	Upsert(ctx context.Context, keyName string, valueEncrypted []byte, updatedBy *int32) error
	// Delete удаляет ключ (пустое значение через PUT).
	Delete(ctx context.Context, keyName string) error
}

// Cipher — шифрование/расшифровка секретов (adapters/security.SecretCipher),
// тот же, что и для project_credentials.password.
type Cipher interface {
	Encrypt(value string) (string, error)
	Decrypt(token string) (string, error)
}
