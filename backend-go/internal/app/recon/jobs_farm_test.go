package recon

import (
	"encoding/json"
	"testing"
)

// Порт backend/tests/test_farm_jobs.py — кап детальных списков в job.result.
// Счётчики целы, списки (hosts/ips/files/errors) режутся до лимита.

func TestCapResult_truncatesListsKeepsCounters(t *testing.T) {
	payload := map[string]any{
		"hosts_created": 300,
		"ports_created": 900,
		"hosts":         intRange(300),
		"errors":        intRange(250),
	}
	capped := capResult(mustJSON(payload), 200)
	var m map[string]any
	if err := json.Unmarshal(capped, &m); err != nil {
		t.Fatalf("capped not JSON: %v", err)
	}
	if m["hosts_created"] != float64(300) {
		t.Errorf("hosts_created = %v, want 300 (counter untouched)", m["hosts_created"])
	}
	if m["ports_created"] != float64(900) {
		t.Errorf("ports_created = %v, want 900 (counter untouched)", m["ports_created"])
	}
	if got := len(m["hosts"].([]any)); got != 200 {
		t.Errorf("hosts capped to %d, want 200", got)
	}
	if got := len(m["errors"].([]any)); got != 200 {
		t.Errorf("errors capped to %d, want 200", got)
	}
}

func TestCapResult_leavesShortLists(t *testing.T) {
	payload := map[string]any{"ips": []int{1, 2, 3}, "files": []int{}, "errors": []string{"x"}}
	capped := capResult(mustJSON(payload), 200)
	var m map[string]any
	if err := json.Unmarshal(capped, &m); err != nil {
		t.Fatalf("capped not JSON: %v", err)
	}
	if got := len(m["ips"].([]any)); got != 3 {
		t.Errorf("ips len = %d, want 3", got)
	}
	if got := len(m["files"].([]any)); got != 0 {
		t.Errorf("files len = %d, want 0", got)
	}
	if got := len(m["errors"].([]any)); got != 1 {
		t.Errorf("errors len = %d, want 1", got)
	}
}

func intRange(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}
