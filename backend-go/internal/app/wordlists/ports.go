package wordlists

import "context"

// Store — порт хранилища метаданных словарей (реализуется wordlistrepo поверх sqlc).
type Store interface {
	Insert(ctx context.Context, in NewWordlist) (Wordlist, error)
	List(ctx context.Context) ([]Wordlist, error)
	Get(ctx context.Context, id int32) (Wordlist, error)
	// Delete удаляет строку по id; возвращает число удалённых (0 = не было).
	Delete(ctx context.Context, id int32) (int64, error)
}

// Storage — порт объектного хранилища (реализуется adapters/storage.Minio). Тот же
// контракт, что у vulns/users — переиспользуем существующий MinIO-клиент.
type Storage interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
	Get(ctx context.Context, key string) (data []byte, contentType string, err error)
	Delete(ctx context.Context, key string) error
}
