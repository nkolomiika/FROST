package vulns

import (
	"context"
	"reflect"
	"testing"

	"github.com/nkolomiika/frost/internal/apperr"
)

// fakeStore — минимальная in-memory реализация Store для проверки чистой логики.
type fakeStore struct {
	vuln          *Vuln
	assetLink     *AssetLink
	hostLinkCount int64
	deletedLink   int32
	audits        []AuditEntry
}

func (f *fakeStore) GetVuln(_ context.Context, _, _ int32) (*Vuln, error) {
	if f.vuln == nil {
		return nil, ErrNoRows
	}
	v := *f.vuln
	return &v, nil
}
func (f *fakeStore) ListVulns(context.Context, VulnListParams) ([]Vuln, int64, error) {
	return nil, 0, nil
}
func (f *fakeStore) ListVulnsForHost(context.Context, VulnHostListParams) ([]Vuln, int64, error) {
	return nil, 0, nil
}
func (f *fakeStore) HostExistsInProject(context.Context, int32, int32) (bool, error) {
	return true, nil
}
func (f *fakeStore) CreateVuln(context.Context, NewVuln) (int32, error)         { return 1, nil }
func (f *fakeStore) UpdateVuln(context.Context, int32, VulnWrite) error         { return nil }
func (f *fakeStore) PatchVulnStatus(context.Context, int32, string) error       { return nil }
func (f *fakeStore) DeleteVuln(context.Context, int32) error                    { return nil }
func (f *fakeStore) VulnProjectID(context.Context, int32) (int32, error)        { return 0, nil }
func (f *fakeStore) ListVulnAssets(context.Context, int32) ([]AssetLink, error) { return nil, nil }
func (f *fakeStore) FindVulnAsset(context.Context, int32, string, int32) (bool, error) {
	return false, nil
}
func (f *fakeStore) GetVulnAssetLink(_ context.Context, _, _ int32) (*AssetLink, error) {
	if f.assetLink == nil {
		return nil, ErrNoRows
	}
	l := *f.assetLink
	return &l, nil
}
func (f *fakeStore) CountHostAssetLinks(context.Context, int32) (int64, error) {
	return f.hostLinkCount, nil
}
func (f *fakeStore) InsertVulnAsset(context.Context, int32, string, int32) (*AssetLink, error) {
	return &AssetLink{ID: 1}, nil
}
func (f *fakeStore) DeleteVulnAsset(_ context.Context, linkID int32) error {
	f.deletedLink = linkID
	return nil
}
func (f *fakeStore) AssetInProject(context.Context, string, int32, int32) (bool, error) {
	return true, nil
}
func (f *fakeStore) PrimaryHostID(context.Context, int32) (int32, bool, error) { return 1, true, nil }
func (f *fakeStore) CountVulnComments(context.Context, int32) (int64, error)   { return 0, nil }
func (f *fakeStore) ListVulnComments(context.Context, int32, int32, int32) ([]Comment, error) {
	return nil, nil
}
func (f *fakeStore) ListCommentMentions(context.Context, int32) ([]Mention, error) { return nil, nil }
func (f *fakeStore) GetVulnComment(context.Context, int32, int32) (*Comment, error) {
	return nil, ErrNoRows
}
func (f *fakeStore) ResolveCommentMentionUsers(context.Context, int32, []string) ([]Mention, error) {
	return nil, nil
}
func (f *fakeStore) CreateComment(context.Context, CommentCreateData) (*Comment, error) {
	return &Comment{ID: 1}, nil
}
func (f *fakeStore) UpdateCommentWithMentions(context.Context, int32, string, []Mention) error {
	return nil
}
func (f *fakeStore) DeleteVulnComment(context.Context, int32) error       { return nil }
func (f *fakeStore) ListVulnFiles(context.Context, int32) ([]File, error) { return nil, nil }
func (f *fakeStore) GetFileByID(context.Context, int32) (*File, error)    { return nil, ErrNoRows }
func (f *fakeStore) GetFileForVuln(context.Context, int32, int32) (*File, error) {
	return nil, ErrNoRows
}
func (f *fakeStore) InsertFile(context.Context, NewFile) (*File, error) { return &File{ID: 1}, nil }
func (f *fakeStore) DeleteFile(context.Context, int32) error            { return nil }
func (f *fakeStore) CountFileImagesForVuln(context.Context, int32, []int32) (int64, error) {
	return 0, nil
}
func (f *fakeStore) IsProjectMember(context.Context, int32, int32) (bool, error) { return true, nil }
func (f *fakeStore) InsertVulnStatusNotification(context.Context, int32, int32, int32, int32, string) error {
	return nil
}
func (f *fakeStore) InsertAudit(_ context.Context, e AuditEntry) error {
	f.audits = append(f.audits, e)
	return nil
}

var _ Store = (*fakeStore)(nil)

func isValidation(t *testing.T, err error) {
	t.Helper()
	var e *apperr.Error
	if err == nil || !as(err, &e) || e.Kind != apperr.KindValidation {
		t.Fatalf("ожидалась ValidationError, получено: %v", err)
	}
}

// as — тонкая обёртка errors.As без импорта в каждом тесте.
func as(err error, target **apperr.Error) bool {
	e, ok := err.(*apperr.Error)
	if ok {
		*target = e
	}
	return ok
}

// ─────────────────────────── severity bands ───────────────────────────

func TestSeverityFromCvssScore(t *testing.T) {
	f := func(x float64) *float64 { return &x }
	cases := []struct {
		score *float64
		want  string
	}{
		{nil, SeverityInfo},
		{f(10.0), SeverityCritical},
		{f(9.0), SeverityCritical},
		{f(8.9), SeverityHigh},
		{f(7.0), SeverityHigh},
		{f(6.9), SeverityMedium},
		{f(4.0), SeverityMedium},
		{f(3.9), SeverityLow},
		{f(0.1), SeverityLow},
		{f(0.0), SeverityInfo},
	}
	for _, c := range cases {
		if got := severityFromCvssScore(c.score); got != c.want {
			var s any = "nil"
			if c.score != nil {
				s = *c.score
			}
			t.Errorf("severityFromCvssScore(%v) = %s, want %s", s, got, c.want)
		}
	}
}

// ─────────────────────────── normalize vector ───────────────────────────

func TestNormalizeCvssVector(t *testing.T) {
	v40 := "4.0"
	cases := []struct {
		version, vector string
		want            *string
	}{
		{"4.0", "AV:N/AC:L", ptrStr("CVSS:4.0/AV:N/AC:L")},
		{"4.0", "CVSS:3.1/AV:N/AC:L", ptrStr("CVSS:4.0/AV:N/AC:L")},
		{"4.0", "CVSS:4.0/AV:N", ptrStr("CVSS:4.0/AV:N")},
		{"4.0", "/AV:N", ptrStr("CVSS:4.0/AV:N")},
		{"4.0", "  ", nil},
	}
	for _, c := range cases {
		got := normalizeCvssVector(&c.version, &c.vector)
		if !eqStrPtr(got, c.want) {
			t.Errorf("normalizeCvssVector(%q,%q) = %v, want %v", c.version, c.vector, derefStr(got), derefStr(c.want))
		}
	}
	// nil-версия/вектор → nil
	if normalizeCvssVector(nil, &v40) != nil || normalizeCvssVector(&v40, nil) != nil {
		t.Error("nil version/vector должен давать nil")
	}
}

// ─────────────────────────── apply cvss fields ───────────────────────────

func TestApplyCvssFields_VectorComputesScore(t *testing.T) {
	payload := map[string]any{
		"cvss_version": "4.0",
		"cvss_vector":  "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
	}
	if err := applyCalculatedCvssFields(payload, nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if payload["cvss_version"] != "4.0" {
		t.Errorf("cvss_version = %v", payload["cvss_version"])
	}
	if payload["cvss_vector"] != "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H" {
		t.Errorf("cvss_vector = %v", payload["cvss_vector"])
	}
	score, ok := payload["cvss_score"].(float64)
	if !ok || score != 10.0 {
		t.Errorf("cvss_score = %v (want 10.0)", payload["cvss_score"])
	}
	if got := severityFromCvssScore(asFloatPtr(payload["cvss_score"])); got != SeverityCritical {
		t.Errorf("derived severity = %s", got)
	}
}

func TestApplyCvssFields_ExplicitClear(t *testing.T) {
	payload := map[string]any{"cvss_vector": nil}
	if err := applyCalculatedCvssFields(payload, ptrStr("4.0"), ptrStr("CVSS:4.0/AV:N")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, k := range []string{"cvss_version", "cvss_vector", "cvss_score"} {
		if v, ok := payload[k]; !ok || v != nil {
			t.Errorf("%s = %v (want present nil)", k, v)
		}
	}
}

func TestApplyCvssFields_ExplicitScoreWithoutVector(t *testing.T) {
	payload := map[string]any{"cvss_score": 5.0}
	isValidation(t, applyCalculatedCvssFields(payload, nil, nil))
}

func TestApplyCvssFields_VersionOnly(t *testing.T) {
	payload := map[string]any{"cvss_version": "4.0"}
	isValidation(t, applyCalculatedCvssFields(payload, nil, nil))
}

func TestApplyCvssFields_ClearWithExplicitScore(t *testing.T) {
	payload := map[string]any{"cvss_vector": "", "cvss_score": 5.0}
	isValidation(t, applyCalculatedCvssFields(payload, nil, nil))
}

// ─────────────────────────── mention dedupe ───────────────────────────

func TestExtractMentionsDedupe(t *testing.T) {
	got := extractMentions("hi @alice and @bob, again @alice — @alice.dev @bad!name")
	want := []string{"alice", "bob", "alice.dev", "bad"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("extractMentions = %v, want %v", got, want)
	}
}

// ─────────────────────────── normalize workflow steps ───────────────────────────

func TestNormalizeWorkflowSteps(t *testing.T) {
	empty := ptrStr("   ")
	desc := ptrStr("  do the thing  ")
	steps := []WorkflowStep{
		{ID: "", Description: empty, ImageFileIDs: []int32{0}},            // отбрасывается (пусто)
		{ID: "keep-1", Description: desc, ImageFileIDs: []int32{0, 5, 7}}, // остаётся
	}
	out := normalizeWorkflowSteps(steps)
	if len(out) != 1 {
		t.Fatalf("ожидался 1 шаг, получено %d", len(out))
	}
	s := out[0]
	if s.ID != "keep-1" {
		t.Errorf("id = %q", s.ID)
	}
	if s.Description == nil || *s.Description != "do the thing" {
		t.Errorf("description = %v", s.Description)
	}
	if !reflect.DeepEqual(s.ImageFileIDs, []int32{5, 7}) {
		t.Errorf("image_file_ids = %v", s.ImageFileIDs)
	}
}

// ─────────────────────────── last-host guard ───────────────────────────

func TestDeleteAsset_LastHostGuard(t *testing.T) {
	store := &fakeStore{
		vuln:          &Vuln{ID: 3, ProjectID: 1, Severity: SeverityInfo, Status: StatusOpen},
		assetLink:     &AssetLink{ID: 4, VulnerabilityID: 3, AssetType: AssetHost, AssetID: 9},
		hostLinkCount: 1,
	}
	svc := NewService(store, nil, "bucket")
	err := svc.DeleteAsset(context.Background(), 1, 3, 4, Actor{ID: 2})
	isValidation(t, err)
	if store.deletedLink != 0 {
		t.Error("связь не должна была удаляться при последней HOST-привязке")
	}
}

func TestDeleteAsset_NonLastHostSucceeds(t *testing.T) {
	store := &fakeStore{
		vuln:          &Vuln{ID: 3, ProjectID: 1, Severity: SeverityInfo, Status: StatusOpen},
		assetLink:     &AssetLink{ID: 4, VulnerabilityID: 3, AssetType: AssetHost, AssetID: 9},
		hostLinkCount: 2,
	}
	svc := NewService(store, nil, "bucket")
	if err := svc.DeleteAsset(context.Background(), 1, 3, 4, Actor{ID: 2}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.deletedLink != 4 {
		t.Errorf("ожидалось удаление связи 4, получено %d", store.deletedLink)
	}
}

// ─────────────────────────── helpers ───────────────────────────

func ptrStr(s string) *string { return &s }
func eqStrPtr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
func derefStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
