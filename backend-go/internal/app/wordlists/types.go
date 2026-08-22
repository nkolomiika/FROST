// Package wordlists — use-cases пользовательских словарей (кастомные wordlists)
// recon-фермы. Метаданные лежат в Postgres (recon_wordlists), сами байты — в MinIO
// под СЕРВЕРНЫМ ключом (имя файла пользователя в путь не идёт). Ферма получает путь
// к словарю ТОЛЬКО через Materialize — единственное место, что отдаёт путь бинарю.
package wordlists

import "time"

// MaxUploadBytes — верхний предел размера загружаемого словаря (50 МБ). Больше —
// отказ (защита от заливки гигантских/мусорных файлов в хранилище).
const MaxUploadBytes int64 = 50 << 20

// objectKeyPrefix — префикс серверного ключа MinIO. Полный ключ: wordlists/{uuid}.
const objectKeyPrefix = "wordlists/"

// Wordlist — метаданные одного кастомного словаря (workspace-level).
type Wordlist struct {
	ID         int32
	Name       string // ярлык (имя файла пользователя), НЕ путь
	ObjectKey  string // серверный ключ MinIO
	SizeBytes  *int64
	Lines      *int32
	UploadedBy *int32
	CreatedAt  time.Time
}

// NewWordlist — вход для вставки метаданных после успешной загрузки в MinIO.
type NewWordlist struct {
	Name       string
	ObjectKey  string
	SizeBytes  *int64
	Lines      *int32
	UploadedBy *int32
}

// BundledTier — забандленный в образ тир-словарь поддоменов (n0kovo). Пользователь
// выбирает его размером ("small|medium|large"), файл маппит FROST.
type BundledTier struct {
	Tier  string `json:"tier"`
	Lines *int32 `json:"lines,omitempty"`
}

// Listing — ответ GET /recon/wordlists: забандленные тиры + кастомные словари.
type Listing struct {
	Bundled []BundledTier `json:"bundled"`
	Custom  []Wordlist    `json:"custom"`
}
