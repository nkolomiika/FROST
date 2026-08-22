package http

import "github.com/nkolomiika/frost/internal/apperr"

// maxBulkItems — предел размера пакета в bulk-операциях (защита от гигантских тел
// и разросшихся IN/ANY-списков). Дубликаты схлопываются до проверки лимита.
const maxBulkItems = 5000

// bulkIDsRequest — тело bulk-delete эндпоинтов по числовым id.
type bulkIDsRequest struct {
	IDs []int32 `json:"ids"`
}

// bulkIPsRequest — тело bulk-скрытия IP-адресов.
type bulkIPsRequest struct {
	IPs []string `json:"ips"`
}

// dedupIDs схлопывает дубликаты (порядок первого вхождения) и проверяет лимит.
// Пустой список допустим (сервис трактует как no-op).
func dedupIDs(ids []int32) ([]int32, error) {
	seen := make(map[int32]struct{}, len(ids))
	out := make([]int32, 0, len(ids))
	for _, id := range ids {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	if len(out) > maxBulkItems {
		return nil, apperr.Validation("Слишком большой пакет")
	}
	return out, nil
}

// dedupStrings схлопывает дубликаты непустых строк (после тримминга сервисом) и
// проверяет лимит. Тримминг/финальный дедуп делает сервис; здесь — только защита
// от чрезмерного тела до вызова сервиса.
func dedupStrings(items []string) ([]string, error) {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, it := range items {
		if _, ok := seen[it]; ok {
			continue
		}
		seen[it] = struct{}{}
		out = append(out, it)
	}
	if len(out) > maxBulkItems {
		return nil, apperr.Validation("Слишком большой пакет")
	}
	return out, nil
}
