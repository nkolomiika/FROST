// Package integrations — use-cases workspace-level API-ключей внешних сервисов
// (OSINT-токены). Значения шифруются тем же Fernet-шифром, что и
// project_credentials.password; наружу секреты не отдаются — только факт
// «configured». Сканеры берут расшифрованный ключ через GetIntegrationKey.
package integrations

import "time"

// Известные key_name сервисов. Список отдаётся целиком (даже неустановленные —
// configured=false), чтобы фронт показал полный набор интеграций.
const (
	KeyGithubToken = "github_token"
	KeyHIBP        = "hibp"
	KeyDehashed    = "dehashed"
	KeyIntelX      = "intelx"
	KeyLeakCheck   = "leakcheck"
	KeySnusbase    = "snusbase"
	KeyProxyNova   = "proxynova"
)

// KnownKeys — стабильный порядок известных ключей (порядок = порядок вывода).
var KnownKeys = []string{
	KeyGithubToken,
	KeyHIBP,
	KeyDehashed,
	KeyIntelX,
	KeyLeakCheck,
	KeySnusbase,
	KeyProxyNova,
}

// IsKnownKey — принадлежит ли имя набору известных сервисов.
func IsKnownKey(name string) bool {
	for _, k := range KnownKeys {
		if k == name {
			return true
		}
	}
	return false
}

// Item — элемент ответа GET/PUT: имя ключа, установлен ли он и когда обновлён.
// Секрет НИКОГДА не входит в Item.
type Item struct {
	KeyName    string     `json:"key_name"`
	Configured bool       `json:"configured"`
	UpdatedAt  *time.Time `json:"updated_at"`
}

// StoredMeta — метаданные строки без значения (для List из Store).
type StoredMeta struct {
	KeyName   string
	UpdatedAt time.Time
}
