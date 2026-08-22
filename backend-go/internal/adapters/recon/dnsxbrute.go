package recon

import (
	"context"
	"os/exec"
	"strconv"
)

// Активный брут поддоменов через dnsx по тир-словарю. Порт «active_brute» стека.
// Запускается ТОЛЬКО в режимах active/both полного прогона фермы. Отсутствие
// бинаря или файла словаря — не ошибка: стадия деградирует молча.

// DNSXBruteConfig — параметры одного брут-прогона.
type DNSXBruteConfig struct {
	WordlistPath string // путь к тир-словарю (см. WordlistPath)
	RateLimit    int    // dnsx -rl (rps)
	Threads      int    // dnsx -t (конкурентность)
}

// DNSXBruteArgs собирает аргументы командной строки dnsx для брута одного корня.
// Вынесено отдельно, чтобы UI/прогресс мог показать точную команду и это же
// покрыть тестом без запуска бинаря.
func DNSXBruteArgs(root string, cfg DNSXBruteConfig) []string {
	args := []string{"-d", root, "-w", cfg.WordlistPath, "-silent", "-no-color"}
	if cfg.RateLimit > 0 {
		args = append(args, "-rl", strconv.Itoa(cfg.RateLimit))
	}
	if cfg.Threads > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.Threads))
	}
	return args
}

// DNSXBrute гоняет `dnsx -d root -w <wordlist> -silent -rl -t` и возвращает
// найденные поддомены в scope корня. Нет бинаря или словаря — пусто (не ошибка).
func DNSXBrute(ctx context.Context, root string, cfg DNSXBruteConfig, s Settings) ([]string, string) {
	// safeHost: root идёт в argv (-d root) — значение с ведущим '-' бинарь принял бы
	// за флаг; такие корни пропускаем (не ошибка). Путь словаря — всегда серверный.
	if !lookPathOK(s.DnsxBin) || !WordlistExists(cfg.WordlistPath) || !safeHost(root) {
		return nil, ""
	}
	c, cancel := context.WithTimeout(ctx, s.DnsxBruteTimeout)
	defer cancel()
	cmd := exec.CommandContext(c, s.DnsxBin, DNSXBruteArgs(root, cfg)...)
	out, err := cmd.Output()
	if err != nil {
		return nil, "dnsx(" + root + "): " + errName(err)
	}
	// Формат вывода — список hostname по строкам, как у subfinder.
	return ParseSubfinder(string(out), root), ""
}
