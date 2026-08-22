// Package leaks — use-cases ЕДИНОГО хранилища утечек (recon_leaks). Разные
// источники (github/linkedin/hibp/…) кладут находки в один «карантин» проекта;
// пользователь смотрит их, импортирует выбранное (создаются project_notes) и чистит.
// Github-скан — первый источник; остальные добавляются как новый source без
// изменения этой модели.
package leaks

import "encoding/json"

// Источники утечек (source). Список открытый — новые сканеры добавляют свой source.
const (
	SourceGithub    = "github"
	SourceLinkedin  = "linkedin"
	SourceHIBP      = "hibp"
	SourceDehashed  = "dehashed"
	SourceIntelX    = "intelx"
	SourceLeakCheck = "leakcheck"
	SourceSnusbase  = "snusbase"
	SourceProxyNova = "proxynova"
)

// Типы находок (kind).
const (
	KindSecret     = "secret"
	KindCredential = "credential"
	KindKey        = "key"
)

// Leak — одна строка отчёта утечек (для провода наружу). Detail — сырой JSON полей
// источника (для github: {repo,file,link,detector,verified}).
type Leak struct {
	ID       int32           `json:"id"`
	Source   string          `json:"source"`
	Kind     string          `json:"kind"`
	Subject  *string         `json:"subject"`
	Value    *string         `json:"value"`
	Detail   json.RawMessage `json:"detail"`
	Verified bool            `json:"verified"`
	Imported bool            `json:"imported"`
}

// LeakInput — вход вставки одной утечки (пишут сканеры через RecordLeaks).
type LeakInput struct {
	ProjectID int32
	JobID     *int32
	Source    string
	Kind      string
	Subject   *string
	Value     *string
	Detail    []byte // JSON, nil = NULL
	Verified  bool
}

// Summary — агрегаты отчёта утечек.
type Summary struct {
	Total    int            `json:"total"`
	Verified int            `json:"verified"`
	Imported int            `json:"imported"`
	BySource map[string]int `json:"by_source"`
}

// Report — отчёт утечек проекта (все источники или отфильтрованные по source/job_id).
type Report struct {
	JobID   *int32  `json:"job_id"`
	Source  *string `json:"source"`
	Summary Summary `json:"summary"`
	Leaks   []Leak  `json:"leaks"`
}

// Filter — необязательные фильтры выборки (nil = не фильтровать).
type Filter struct {
	Source *string
	JobID  *int32
}

// ImportResult — итог импорта выбранных утечек в проект.
type ImportResult struct {
	Imported int `json:"imported"`
}
