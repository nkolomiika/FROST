// Package http — HTTP-адаптер: chi-роутер, middleware и хендлеры.
// На фазе 0 здесь только базовый роутер с /health; доменные роуты добавляются
// по мере переноса эндпоинтов (генерируются oapi-codegen из docs/openapi-v*.json).
package http

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// Deps — зависимости HTTP-слоя (composition root передаёт сюда адаптеры).
type Deps struct {
	Logger        *slog.Logger
	Auth          *AuthHandler          // nil до подключения контекста auth
	Audit         *AuditHandler         // nil до подключения контекста audit
	AgentTokens   *AgentTokenHandler    // nil до подключения контекста agenttokens
	Projects      *ProjectsHandler      // nil до подключения контекста projects
	Inventory     *InventoryHandler     // nil до подключения контекста inventory
	Vulns         *VulnsHandler         // nil до подключения контекста vulns
	Users         *UsersHandler         // nil до подключения контекста users
	AgentV2       *AgentV2Handler       // nil до подключения /api/v2
	Notifications *NotificationsHandler // nil до подключения notifications
	Recon         *ReconHandler         // nil до подключения recon (ферма+scanner)
	Reports       *ReportsHandler       // nil до подключения reports
}

// NewRouter собирает chi-роутер с базовыми middleware и служебными эндпоинтами.
func NewRouter(d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(requestLogger(d.Logger))

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// Перенесённые в Go контексты (strangler): auth. Остальные пути на время
	// миграции обслуживает Python-бэкенд (маршрутизирует nginx).
	if d.Auth != nil {
		d.Auth.Register(r)
	}
	if d.Audit != nil {
		d.Audit.Register(r)
	}
	if d.AgentTokens != nil {
		d.AgentTokens.Register(r)
	}
	if d.Projects != nil {
		d.Projects.Register(r)
	}
	if d.Inventory != nil {
		d.Inventory.Register(r)
	}
	if d.Vulns != nil {
		d.Vulns.Register(r)
	}
	if d.Users != nil {
		d.Users.Register(r)
	}
	if d.AgentV2 != nil {
		d.AgentV2.Register(r)
	}
	if d.Notifications != nil {
		d.Notifications.Register(r)
	}
	if d.Recon != nil {
		d.Recon.Register(r)
	}
	if d.Reports != nil {
		d.Reports.Register(r)
	}

	return r
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
