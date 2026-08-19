// Package log настраивает структурированный логгер приложения (log/slog).
package log

import (
	"log/slog"
	"os"
)

// New возвращает slog.Logger. В debug-режиме — текстовый вывод с уровнем Debug,
// иначе JSON с уровнем Info (удобно для сбора логов в проде).
func New(debug bool) *slog.Logger {
	level := slog.LevelInfo
	var handler slog.Handler
	if debug {
		level = slog.LevelDebug
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	return slog.New(handler)
}
