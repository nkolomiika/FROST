package http

import (
	"encoding/json"
	"net/http"

	"github.com/nkolomiika/frost/internal/apperr"
)

// writeError отдаёт доменную ошибку как {"detail": "..."} с корректным статусом
// (зеркало exception-хендлеров app/main.py).
func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, apperr.HTTPStatus(err), map[string]string{"detail": apperr.Detail(err)})
}

// decodeJSON читает тело запроса в v; при ошибке возвращает 422-доменную ошибку.
func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return apperr.Validation("Некорректное тело запроса")
	}
	return nil
}

// ptr возвращает указатель на значение — для *T-полей сгенерированных DTO.
func ptr[T any](v T) *T { return &v }

// ptrIfNonEmpty возвращает *string или nil для пустой строки.
func ptrIfNonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
