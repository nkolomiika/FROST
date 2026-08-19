package http

import (
	"math"
	"net/http"
	"strconv"
)

// pagesCount = max(1, ceil(total/size)) — форма из to_paginated_response (Python).
func pagesCount(total int64, size int) int {
	if total <= 0 || size <= 0 {
		return 1
	}
	return int(math.Ceil(float64(total) / float64(size)))
}

// paginated собирает конверт постраничного ответа {items,total,page,size,pages}.
func paginated(items any, total int64, page, size int) map[string]any {
	return map[string]any{
		"items": items,
		"total": total,
		"page":  page,
		"size":  size,
		"pages": pagesCount(total, size),
	}
}

// intQuery читает целочисленный query-параметр с дефолтом и границами [min,max].
func intQuery(r *http.Request, name string, def, min, max int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < min {
		v = min
	}
	if v > max {
		v = max
	}
	return v
}
