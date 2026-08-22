package recon

import (
	"bufio"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// lineCountCap — верхняя граница подсчёта строк при перечислении (Enumerate).
// n0kovo/SecLists-файлы бывают на миллионы строк; полный подсчёт для листинга не
// нужен — считаем до потолка и отдаём min(реальное, cap), не читая файл целиком.
const lineCountCap = 5_000_000

// WordlistFile — один словарь на диске (в WordlistDir), отдаётся наружу по
// ОРИГИНАЛЬНОМУ имени. Path — путь ОТНОСИТЕЛЬНО WordlistDir (напр.
// "seclists/Discovery/DNS/subdomains-top1million-5000.txt" или
// "n0kovo_subdomains_small.txt"); Name — базовое имя файла; Category — каталог
// файла относительно WordlistDir ("seclists/Discovery/DNS"), для файлов в корне —
// "n0kovo"; Lines — дешёвый подсчёт строк с потолком lineCountCap.
type WordlistFile struct {
	Name     string
	Path     string
	Category string
	Lines    int
}

// EnumerateWordlists РЕКУРСИВНО обходит WordlistDir и возвращает все *.txt по их
// оригинальным именам (SecLists + n0kovo). Пустые/нечитаемые файлы пропускаются
// (частичная загрузка в образе). Сортировка стабильная (по Path). Каталога нет —
// не ошибка, а пустой список (образ без словарей → ферма деградирует молча).
func EnumerateWordlists() ([]WordlistFile, error) {
	dir := WordlistDir()
	var out []WordlistFile
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			// Битую запись пропускаем, обход не валим.
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(d.Name()), ".txt") {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() == 0 {
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		out = append(out, WordlistFile{
			Name:     d.Name(),
			Path:     rel,
			Category: wordlistCategory(rel),
			Lines:    countLinesCapped(p, lineCountCap),
		})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// wordlistCategory — каталог файла относительно WordlistDir. Файл в корне (n0kovo)
// → "n0kovo"; иначе — путь каталога ("seclists/Discovery/DNS").
func wordlistCategory(rel string) string {
	d := filepath.ToSlash(filepath.Dir(rel))
	if d == "." || d == "" {
		return "n0kovo"
	}
	return d
}

// countLinesCapped — дешёвый подсчёт строк: считает '\n' потоково и ОСТАНАВЛИВАЕТСЯ
// на потолке cap (файл целиком не читается для огромных словарей). Возвращает
// оценку числа строк; для файла без хвостового '\n' последняя строка учитывается.
func countLinesCapped(path string, cap int) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReaderSize(f, 64<<10)
	buf := make([]byte, 64<<10)
	count := 0
	sawData := false
	lastByte := byte('\n')
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			sawData = true
			lastByte = buf[n-1]
		}
		for i := 0; i < n; i++ {
			if buf[i] == '\n' {
				count++
				if count >= cap {
					return count
				}
			}
		}
		if rerr != nil {
			break // io.EOF или иная ошибка — считаем то, что прочли
		}
	}
	// Непустой хвост без завершающего '\n' — ещё одна строка.
	if sawData && lastByte != '\n' {
		count++
	}
	return count
}

// cleanWordlistRel синтаксически валидирует относительный путь словаря: непустой,
// НЕ абсолютный, без выхода за пределы каталога ('..'). Возвращает вычищенный
// (filepath.Clean) относительный путь и ok. Файловую систему НЕ трогает —
// существование проверяет ResolveWordlistPath.
func cleanWordlistRel(rel string) (string, bool) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", false
	}
	clean := filepath.Clean(filepath.FromSlash(rel))
	// После Clean путь не должен быть '.', абсолютным или начинаться с '..' (это
	// единственные формы выхода за пределы каталога, оставшиеся после Clean).
	if clean == "." || filepath.IsAbs(clean) {
		return "", false
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return filepath.ToSlash(clean), true
}

// SanitizeWordlistRelPath — синтаксическая нормализация пользовательского выбора
// словаря по пути для FarmConfig: возвращает вычищенный относительный путь или ""
// для невалидного (абсолютный / '..' / пустой). Существование НЕ проверяется —
// конфиг сохраняется даже если файла нет на этом узле; финальная валидация с
// проверкой файла — в ResolveWordlistPath на запуске инструмента.
func SanitizeWordlistRelPath(rel string) string {
	clean, ok := cleanWordlistRel(rel)
	if !ok {
		return ""
	}
	return clean
}

// ResolveWordlistPath — АВТОРИТЕТНАЯ серверная валидация пути забандленного словаря
// перед передачей инструменту (dnsx/ffuf). Синтаксическая проверка (cleanWordlistRel:
// не абсолютный, без '..'), затем Join с WordlistDir и Rel-prefix-check (путь ОБЯЗАН
// остаться под WordlistDir — никакой traversal наружу), затем WordlistExists (файл
// есть и не пуст). Возвращает АБСОЛЮТНЫЙ путь и ok. Пользовательская строка сюда
// приходит только как относительный выбор — наружу WordlistDir выйти нельзя.
func ResolveWordlistPath(rel string) (string, bool) {
	clean, ok := cleanWordlistRel(rel)
	if !ok {
		return "", false
	}
	dir := WordlistDir()
	abs := filepath.Join(dir, clean)
	// Двойная защита: даже после Clean убеждаемся, что abs реально под dir.
	back, err := filepath.Rel(dir, abs)
	if err != nil || back == ".." || strings.HasPrefix(back, ".."+string(os.PathSeparator)) {
		return "", false
	}
	if !WordlistExists(abs) {
		return "", false
	}
	return abs, true
}
