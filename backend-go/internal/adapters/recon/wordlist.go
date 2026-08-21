package recon

import (
	"os"
	"path/filepath"
)

// Тиры словарей поддоменов, бандлятся в образ recon-worker (см. Dockerfile).
// Пользователь тир НЕ выбирает файлом — только размер "small|medium|large",
// FROST маппит его на конкретный файл здесь.

// DefaultWordlistDir — базовый каталог со словарями в образе recon-worker.
// Переопределяется env RECON_WORDLIST_DIR.
const DefaultWordlistDir = "/usr/local/share/frost-wordlists"

// имена файлов тиров (n0kovo_subdomains: small/medium/huge).
const (
	wordlistSmall  = "n0kovo_subdomains_small.txt"
	wordlistMedium = "n0kovo_subdomains_medium.txt"
	wordlistLarge  = "n0kovo_subdomains_huge.txt"
)

// WordlistDir возвращает каталог словарей: env RECON_WORDLIST_DIR либо дефолт.
func WordlistDir() string {
	if d := os.Getenv("RECON_WORDLIST_DIR"); d != "" {
		return d
	}
	return DefaultWordlistDir
}

// wordlistFileForSize — имя файла тира по размеру (medium — дефолт для пустого/
// неизвестного значения).
func wordlistFileForSize(size string) string {
	switch size {
	case "small":
		return wordlistSmall
	case "large":
		return wordlistLarge
	default:
		return wordlistMedium
	}
}

// WordlistPath — полный путь к файлу словаря выбранного тира. Каталог — WordlistDir().
func WordlistPath(size string) string {
	return filepath.Join(WordlistDir(), wordlistFileForSize(size))
}

// WordlistExists — файл тира реально присутствует, читаем (не каталог) и НЕ пуст.
// Проверка размера важна: частичная/оборванная загрузка в образе может оставить
// 0-байтный файл — брут по нему бессмысленен, лучше молча деградировать.
func WordlistExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir() && info.Size() > 0
}
