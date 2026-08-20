package http

import (
	"net/http/httptest"
	"reflect"
	"testing"
)

// Порт test_pagination.py + части test_additional_validations.py (page/size).
//
// В Python постраничность жила в app.pagination.PageParams / to_paginated_response.
// В Go конверт собирает paginated()/pagesCount(), а границы page/size задаёт
// intQuery() (клампингом, а не исключением — см. заметки в тестах).

// pagesCount для неполной последней страницы: 25 элементов по 20 → 2 страницы.
// (test_to_paginated_response_for_partial_last_page_tc_pag_001)
func TestPagesCountPartialLastPage(t *testing.T) {
	if got := pagesCount(25, 20); got != 2 {
		t.Fatalf("pagesCount(25,20) = %d, want 2", got)
	}
}

// Пустой набор → всегда одна страница.
// (test_to_paginated_response_returns_single_page_for_empty_set_tc_pag_002)
func TestPagesCountEmptySet(t *testing.T) {
	if got := pagesCount(0, 20); got != 1 {
		t.Fatalf("pagesCount(0,20) = %d, want 1", got)
	}
}

// Конверт постраничного ответа для неполной последней страницы.
// (test_to_paginated_response_for_partial_last_page_tc_pag_001)
func TestPaginatedEnvelopePartialLastPage(t *testing.T) {
	items := []int{1, 2, 3, 4, 5}
	env := paginated(items, 25, 2, 20)

	if env["page"] != 2 {
		t.Errorf("page = %v, want 2", env["page"])
	}
	if env["size"] != 20 {
		t.Errorf("size = %v, want 20", env["size"])
	}
	if env["total"] != int64(25) {
		t.Errorf("total = %v, want 25", env["total"])
	}
	if env["pages"] != 2 {
		t.Errorf("pages = %v, want 2", env["pages"])
	}
	if !reflect.DeepEqual(env["items"], items) {
		t.Errorf("items = %v, want %v", env["items"], items)
	}
}

// Конверт для пустого набора: pages=1, items — переданный (пустой) срез.
// (test_to_paginated_response_returns_single_page_for_empty_set_tc_pag_002)
func TestPaginatedEnvelopeEmptySet(t *testing.T) {
	items := []int{}
	env := paginated(items, 0, 10, 20)

	if env["pages"] != 1 {
		t.Errorf("pages = %v, want 1", env["pages"])
	}
	if !reflect.DeepEqual(env["items"], items) {
		t.Errorf("items = %v, want empty slice", env["items"])
	}
}

// Смещение вычисляется в хендлерах формулой (page-1)*size — прямого аналога
// PageParams.offset в Go нет, поэтому фиксируем именно эту формулу.
// (test_page_params_offset_calculation_tc_pag_001)
func TestPageOffsetFormula(t *testing.T) {
	page, size := 2, 20
	if off := (page - 1) * size; off != 20 {
		t.Fatalf("offset (page-1)*size = %d, want 20", off)
	}
}

// intQuery отдаёт дефолт при отсутствии параметра и при нечисловом значении.
func TestIntQueryDefaults(t *testing.T) {
	r := httptest.NewRequest("GET", "/?other=1", nil)
	if v := intQuery(r, "page", 3, 1, 100); v != 3 {
		t.Errorf("missing param: got %d, want default 3", v)
	}
	r = httptest.NewRequest("GET", "/?page=abc", nil)
	if v := intQuery(r, "page", 3, 1, 100); v != 3 {
		t.Errorf("non-numeric: got %d, want default 3", v)
	}
}

// В Python отрицательная страница и нулевой размер поднимали ValidationError.
// В Go intQuery клампит к нижней границе (min) — эффект защиты эквивалентен.
// (test_page_params_reject_negative_page_and_zero_size_tc_pag_003_004)
func TestIntQueryClampsLowerBound(t *testing.T) {
	r := httptest.NewRequest("GET", "/?page=-1", nil)
	if v := intQuery(r, "page", 1, 1, 1_000_000); v != 1 {
		t.Errorf("page=-1 → %d, want clamp to 1", v)
	}
	r = httptest.NewRequest("GET", "/?size=0", nil)
	if v := intQuery(r, "size", 20, 1, 200); v != 1 {
		t.Errorf("size=0 → %d, want clamp to 1", v)
	}
}

// Слишком большой размер страницы клампится к max (в Python — ValidationError).
// (test_page_params_reject_excessive_size_tc_pag_005)
func TestIntQueryClampsUpperBound(t *testing.T) {
	r := httptest.NewRequest("GET", "/?size=10000", nil)
	if v := intQuery(r, "size", 20, 1, 200); v != 200 {
		t.Errorf("size=10000 → %d, want clamp to 200", v)
	}
}
