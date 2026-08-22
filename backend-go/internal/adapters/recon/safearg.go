package recon

import "strings"

// Защита от flag-инъекции в argv инструментов рекона. Все вызовы — exec.Command
// (без shell), так что shell-инъекции нет; остаётся риск, что пользовательское
// значение (host/url), начинающееся с '-', будет воспринято бинарём как ФЛАГ.
// safeArg отсекает такие значения, а вызывающий их пропускает. Пути к словарям
// сюда не относятся — они всегда серверные (temp/bundled), см. MaterializeWordlist.

// safeArg — значение безопасно передавать как позиционный/значимый argv-токен:
// непустое, не начинается с '-' (иначе бинарь примет его за флаг) и без пробелов/
// управляющих символов, которые в argv быть не должны.
func safeArg(v string) bool {
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "-") {
		return false
	}
	for _, r := range v {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' || r < 0x20 {
			return false
		}
	}
	return true
}

// safeHost — host пригоден как аргумент инструмента (dnsx -d / url-хоста). Тот же
// критерий, что safeArg (отдельное имя — для читаемости в местах брута/эндпоинтов).
func safeHost(host string) bool { return safeArg(host) }
