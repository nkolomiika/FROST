package http

import (
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/nkolomiika/frost/internal/app/auth"
	"github.com/nkolomiika/frost/internal/app/wordlists"
	"github.com/nkolomiika/frost/internal/apperr"
)

// WordlistHandler обслуживает пользовательские словари recon-фермы (workspace-level,
// /api/v1/recon/wordlists). Файлы лежат в MinIO под серверным ключом; наружу отдаются
// только метаданные. Список читает любой аутентифицированный участник (нужен для
// сборки farm-config), загрузка/удаление — admin (изменение общего workspace-ресурса,
// как workspace-интеграции).
type WordlistHandler struct {
	svc         *wordlists.Service
	auth        *auth.Service
	csrfOrigins []string
}

// NewWordlistHandler собирает обработчик словарей.
func NewWordlistHandler(svc *wordlists.Service, authSvc *auth.Service, csrfOrigins []string) *WordlistHandler {
	return &WordlistHandler{svc: svc, auth: authSvc, csrfOrigins: csrfOrigins}
}

// Register монтирует роуты словарей (GET — auth; POST/DELETE — auth+admin+CSRF).
func (h *WordlistHandler) Register(r chi.Router) {
	r.Route("/api/v1/recon/wordlists", func(ar chi.Router) {
		ar.Use(enforceCSRF(h.csrfOrigins))
		ar.Use(requireAuth(h.auth))
		ar.Get("/", h.list)
		ar.With(requireAdmin).Post("/", h.upload)
		ar.With(requireAdmin).Delete("/{id}", h.delete)
	})
}

// wordlistItem — метаданные словаря наружу (без object_key/uploaded_by).
type wordlistItem struct {
	ID        int32  `json:"id"`
	Name      string `json:"name"`
	SizeBytes *int64 `json:"size_bytes"`
	Lines     *int32 `json:"lines"`
	CreatedAt string `json:"created_at"`
}

func wordlistItemOut(wl wordlists.Wordlist) wordlistItem {
	return wordlistItem{
		ID:        wl.ID,
		Name:      wl.Name,
		SizeBytes: wl.SizeBytes,
		Lines:     wl.Lines,
		CreatedAt: wl.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

// upload принимает multipart-файл (+optional name), валидирует и сохраняет словарь.
func (h *WordlistHandler) upload(w http.ResponseWriter, r *http.Request) {
	// Ограничиваем тело: 50 МБ полезной нагрузки + запас на multipart-обвязку.
	r.Body = http.MaxBytesReader(w, r.Body, wordlists.MaxUploadBytes+(1<<20))
	if err := r.ParseMultipartForm(uploadMaxMemory); err != nil {
		writeError(w, apperr.Validation("Некорректная загрузка файла"))
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, apperr.Validation("Файл не передан"))
		return
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, apperr.Validation("Некорректная загрузка файла"))
		return
	}
	// Имя-ярлык: из поля name, иначе из имени файла (в путь MinIO НЕ идёт).
	name := r.FormValue("name")
	if name == "" && header != nil {
		name = header.Filename
	}
	actor := actorFrom(r).ID
	wl, err := h.svc.Upload(r.Context(), name, data, &actor)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, wordlistItemOut(wl))
}

// list отдаёт бандл-тиры + кастомные словари.
func (h *WordlistHandler) list(w http.ResponseWriter, r *http.Request) {
	listing, err := h.svc.List(r.Context())
	if err != nil {
		writeError(w, err)
		return
	}
	custom := make([]wordlistItem, 0, len(listing.Custom))
	for _, wl := range listing.Custom {
		custom = append(custom, wordlistItemOut(wl))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"bundled": listing.Bundled,
		"custom":  custom,
	})
}

// delete удаляет словарь (объект MinIO + строку метаданных).
func (h *WordlistHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, err := pathInt32(r, "id")
	if err != nil {
		writeError(w, err)
		return
	}
	if err := h.svc.Delete(r.Context(), id); err != nil {
		writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
