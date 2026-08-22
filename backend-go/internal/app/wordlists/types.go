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

// BundledWordlist — один забандленный в образ recon-воркера словарь на диске
// (SecLists + n0kovo), отдаётся наружу по ОРИГИНАЛЬНОМУ имени. Path — путь
// ОТНОСИТЕЛЬНО WordlistDir (им же выбирается словарь в FarmConfig), Name — базовое
// имя, Category — каталог (напр. "seclists/Discovery/DNS" или "n0kovo"), Lines —
// дешёвый подсчёт строк с потолком.
type BundledWordlist struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	Category string `json:"category"`
	Lines    int    `json:"lines"`
}

// Listing — ответ GET /recon/wordlists: реальные забандленные файлы (по именам) +
// кастомные словари workspace.
type Listing struct {
	Bundled []BundledWordlist `json:"bundled"`
	Custom  []Wordlist        `json:"custom"`
}
