package vulns

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// Порт backend/tests/test_vulnerability_workflow.py — паритет поведения
// VulnerabilityService (workflow-шаги, CVSS-поля, гидрация, уведомления о смене
// статуса). Тесты in-package, чтобы дёргать неэкспортируемые хелперы напрямую.

// ─────────────────────────── normalize workflow steps ───────────────────────────

// test_normalize_workflow_steps_discards_empty_entries
func TestNormalizeWorkflowSteps_DiscardsEmptyEntries(t *testing.T) {
	out := normalizeWorkflowSteps([]WorkflowStep{
		{ID: "step-1", Description: ptrStr("  "), ImageFileIDs: []int32{}},
		{ID: "step-2", Description: ptrStr("Войти под тестовым пользователем"), ImageFileIDs: []int32{1}},
	})
	if len(out) != 1 {
		t.Fatalf("ожидался 1 шаг, получено %d (%+v)", len(out), out)
	}
	s := out[0]
	if s.ID != "step-2" {
		t.Errorf("id = %q", s.ID)
	}
	if s.Description == nil || *s.Description != "Войти под тестовым пользователем" {
		t.Errorf("description = %v", s.Description)
	}
	if !reflect.DeepEqual(s.ImageFileIDs, []int32{1}) {
		t.Errorf("image_file_ids = %v", s.ImageFileIDs)
	}
	if s.EndpointID != nil || s.EndpointRequestRaw != nil {
		t.Errorf("endpoint поля должны быть nil: %+v", s)
	}
}

// test_normalize_workflow_steps_keeps_endpoint_only_entries
func TestNormalizeWorkflowSteps_KeepsEndpointOnlyEntries(t *testing.T) {
	out := normalizeWorkflowSteps([]WorkflowStep{
		{ID: "step-3", Description: ptrStr("  "), ImageFileIDs: []int32{}, EndpointRequestRaw: ptrStr("GET /api/ping HTTP/1.1")},
	})
	if len(out) != 1 {
		t.Fatalf("ожидался 1 шаг, получено %d", len(out))
	}
	s := out[0]
	if s.ID != "step-3" {
		t.Errorf("id = %q", s.ID)
	}
	if s.Description != nil {
		t.Errorf("description должен быть nil, получено %v", *s.Description)
	}
	if len(s.ImageFileIDs) != 0 {
		t.Errorf("image_file_ids = %v", s.ImageFileIDs)
	}
	if s.EndpointID != nil {
		t.Errorf("endpoint_id должен быть nil")
	}
	if s.EndpointRequestRaw == nil || *s.EndpointRequestRaw != "GET /api/ping HTTP/1.1" {
		t.Errorf("endpoint_request_raw = %v", s.EndpointRequestRaw)
	}
}

// ─────────────────────────── workflow steps -> text ───────────────────────────

// test_workflow_steps_to_text_renders_numbered_blocks
func TestWorkflowStepsToText_RendersNumberedBlocks(t *testing.T) {
	got := workflowStepsToText([]WorkflowStep{
		{ID: "step-1", Description: ptrStr("Открыть страницу входа"), ImageFileIDs: []int32{}},
		{ID: "step-2", Description: ptrStr("Вставить payload"), ImageFileIDs: []int32{1, 2}},
	})
	want := "1. Этап 1\n" +
		"Открыть страницу входа\n\n" +
		"2. Этап 2\n" +
		"Вставить payload\n" +
		"[Изображений: 2]"
	if got == nil || *got != want {
		t.Errorf("workflowStepsToText =\n%q\nwant\n%q", derefStr(got), want)
	}
}

// ─────────────────────────── calculate cvss score ───────────────────────────

// test_calculate_cvss_score_normalizes_vector_prefix
func TestCalculateCvssScore_NormalizesVectorPrefix(t *testing.T) {
	version := "4.0"
	vector := "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	norm, score, err := calculateCvssScore(&version, &vector)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm == nil || *norm != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" {
		t.Errorf("normalized = %v", derefStr(norm))
	}
	if score == nil || *score != 9.3 {
		t.Errorf("score = %v (want 9.3)", derefStr64(score))
	}
}

// test_calculate_cvss_score_accepts_enum_version
// (в Go версия — строка "4.0"; enum-ветви нет, поведение эквивалентно.)
func TestCalculateCvssScore_AcceptsVersionWithFullVector(t *testing.T) {
	version := "4.0"
	vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	norm, score, err := calculateCvssScore(&version, &vector)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if norm == nil || *norm != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" {
		t.Errorf("normalized = %v", derefStr(norm))
	}
	if score == nil || *score != 9.3 {
		t.Errorf("score = %v (want 9.3)", derefStr64(score))
	}
}

// ─────────────────────────── apply calculated cvss fields ───────────────────────────

// test_apply_calculated_cvss_fields_rejects_score_without_vector
func TestApplyCvssFields_RejectsScoreWithoutVector_NullKeys(t *testing.T) {
	payload := map[string]any{"cvss_version": nil, "cvss_vector": nil, "cvss_score": 9.9}
	err := applyCalculatedCvssFields(payload, nil, nil)
	isValidation(t, err)
	if err == nil || !strings.Contains(err.Error(), "CVSS score рассчитывается автоматически") {
		t.Errorf("ожидалось сообщение про авто-расчёт, получено: %v", err)
	}
}

// test_apply_calculated_cvss_fields_clears_score_when_vector_removed
func TestApplyCvssFields_ClearsScoreWhenVectorRemoved(t *testing.T) {
	payload := map[string]any{"cvss_vector": "", "cvss_score": nil}
	err := applyCalculatedCvssFields(payload, ptrStr("4.0"), ptrStr("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, k := range []string{"cvss_version", "cvss_vector", "cvss_score"} {
		if v, ok := payload[k]; !ok || v != nil {
			t.Errorf("%s = %v (want present nil)", k, v)
		}
	}
}

// ─────────────────────────── hydrate workflow steps ───────────────────────────

// test_hydrate_workflow_steps_uses_legacy_steps_to_reproduce
func TestHydrateWorkflowSteps_UsesLegacyStepsToReproduce(t *testing.T) {
	v := &Vuln{WorkflowStepsRaw: nil, StepsToReproduce: ptrStr("Открыть URL и выполнить payload")}
	hydrateWorkflowSteps(v)
	if len(v.WorkflowSteps) != 1 {
		t.Fatalf("ожидался 1 шаг, получено %d", len(v.WorkflowSteps))
	}
	if v.WorkflowSteps[0].Description == nil || *v.WorkflowSteps[0].Description != "Открыть URL и выполнить payload" {
		t.Errorf("description = %v", v.WorkflowSteps[0].Description)
	}
}

// test_hydrate_workflow_steps_splits_text_only_finding
func TestHydrateWorkflowSteps_SplitsTextOnlyFinding(t *testing.T) {
	v := &Vuln{WorkflowStepsRaw: nil, StepsToReproduce: ptrStr("1. Раз\n2. Два\n3. Три")}
	hydrateWorkflowSteps(v)
	var descs []string
	for _, s := range v.WorkflowSteps {
		if s.Description == nil {
			t.Fatalf("шаг без описания: %+v", s)
		}
		if s.ID == "" {
			t.Errorf("шаг без id: %+v", s)
		}
		descs = append(descs, *s.Description)
	}
	if !reflect.DeepEqual(descs, []string{"Раз", "Два", "Три"}) {
		t.Errorf("descriptions = %v", descs)
	}
}

// test_hydrate_workflow_steps_leaves_existing_steps_alone
func TestHydrateWorkflowSteps_LeavesExistingStepsAlone(t *testing.T) {
	existing := []WorkflowStep{{ID: "s1", Description: ptrStr("Уже разложено"), ImageFileIDs: []int32{}}}
	raw, _ := json.Marshal(existing)
	v := &Vuln{WorkflowStepsRaw: raw, StepsToReproduce: ptrStr("1. Игнор")}
	hydrateWorkflowSteps(v)
	if len(v.WorkflowSteps) != 1 || v.WorkflowSteps[0].ID != "s1" ||
		v.WorkflowSteps[0].Description == nil || *v.WorkflowSteps[0].Description != "Уже разложено" {
		t.Errorf("существующие шаги должны остаться без изменений: %+v", v.WorkflowSteps)
	}
}

// ─────────────────────────── split steps text ───────────────────────────

// test_split_steps_text_drops_numbering (параметризованный) + keeps_continuation
func TestSplitStepsText_DropsNumbering(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"1. Выполнить запрос\n2. Получить ответ", []string{"Выполнить запрос", "Получить ответ"}},
		{"1) Первый\n2) Второй", []string{"Первый", "Второй"}},
		{"- Пункт A\n- Пункт B", []string{"Пункт A", "Пункт B"}},
		{"Одна строка", []string{"Одна строка"}},
		{"", nil},
	}
	for _, c := range cases {
		got := splitStepsText(c.text)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("splitStepsText(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}

// test_split_steps_text_keeps_continuation_with_its_step
func TestSplitStepsText_KeepsContinuationWithItsStep(t *testing.T) {
	got := splitStepsText("1. Шаг\nпродолжение\n2. Второй")
	if !reflect.DeepEqual(got, []string{"Шаг\nпродолжение", "Второй"}) {
		t.Errorf("splitStepsText = %v", got)
	}
}

// ─────────────────────────── validate workflow step images ───────────────────────────

// test_validate_workflow_step_images_rejects_foreign_file_ids
func TestValidateWorkflowStepImages_RejectsForeignFileIDs(t *testing.T) {
	svc := NewService(&fakeStore{}, nil, "bucket") // CountFileImagesForVuln → 0
	vulnID := int32(5)
	err := svc.validateWorkflowStepImages(context.Background(), &vulnID,
		[]WorkflowStep{{ID: "step-1", Description: nil, ImageFileIDs: []int32{9}}})
	isValidation(t, err)
	if err == nil || !strings.Contains(err.Error(), "workflow_steps.image_file_ids") {
		t.Errorf("ожидалось сообщение про workflow_steps.image_file_ids, получено: %v", err)
	}
}

// ─────────────────────────── status-change notification ───────────────────────────

type statusNotif struct {
	userID, vulnID, projectID, actorID int32
	status                             string
}

// notifyStore расширяет fakeStore: делает статус мутабельным (PatchVulnStatus →
// GetVuln возвращает новый статус) и записывает уведомления о смене статуса.
type notifyStore struct {
	*fakeStore
	notifs []statusNotif
}

func (n *notifyStore) PatchVulnStatus(_ context.Context, _ int32, status string) error {
	n.fakeStore.vuln.Status = status
	return nil
}

func (n *notifyStore) InsertVulnStatusNotification(_ context.Context, userID, vulnID, projectID, actorID int32, status string) error {
	n.notifs = append(n.notifs, statusNotif{userID, vulnID, projectID, actorID, status})
	return nil
}

func newNotifyStore(v *Vuln) *notifyStore {
	return &notifyStore{fakeStore: &fakeStore{vuln: v}}
}

// test_status_change_notifies_the_reporter
func TestStatusChange_NotifiesTheReporter(t *testing.T) {
	store := newNotifyStore(&Vuln{ID: 5, ProjectID: 1, CreatedBy: 42, Status: StatusOpen})
	svc := NewService(store, nil, "bucket")
	if _, err := svc.PatchStatus(context.Background(), 1, 5, StatusWontFix, Actor{ID: 7}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(store.notifs) != 1 {
		t.Fatalf("ожидалось 1 уведомление, получено %d", len(store.notifs))
	}
	n := store.notifs[0]
	if n.userID != 42 {
		t.Errorf("уведомление должно уйти автору (42), а ушло %d", n.userID)
	}
	if n.vulnID != 5 {
		t.Errorf("vulnID = %d", n.vulnID)
	}
	if n.status != "wont_fix" {
		t.Errorf("status = %q (want wont_fix)", n.status)
	}
}

// test_status_change_by_the_reporter_notifies_nobody
func TestStatusChange_ByTheReporterNotifiesNobody(t *testing.T) {
	store := newNotifyStore(&Vuln{ID: 5, ProjectID: 1, CreatedBy: 42, Status: StatusOpen})
	svc := NewService(store, nil, "bucket")
	if _, err := svc.PatchStatus(context.Background(), 1, 5, StatusFixed, Actor{ID: 42}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(store.notifs) != 0 {
		t.Errorf("автор менял свой статус — уведомлять некого, получено %+v", store.notifs)
	}
}

// test_same_status_notifies_nobody
func TestStatusChange_SameStatusNotifiesNobody(t *testing.T) {
	store := newNotifyStore(&Vuln{ID: 5, ProjectID: 1, CreatedBy: 42, Status: StatusOpen})
	svc := NewService(store, nil, "bucket")
	if _, err := svc.PatchStatus(context.Background(), 1, 5, StatusOpen, Actor{ID: 7}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(store.notifs) != 0 {
		t.Errorf("статус не изменился — уведомлять некого, получено %+v", store.notifs)
	}
}

// ─────────────────────────── helpers ───────────────────────────

func derefStr64(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}
