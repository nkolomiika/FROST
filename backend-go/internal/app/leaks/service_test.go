package leaks

import (
	"context"
	"testing"
)

// fakeStore — in-memory реализация Store с автоинкрементом id.
type fakeStore struct {
	seq      int32
	rows     []Leak           // «БД» утечек
	rowProj  map[int32]int32  // id → project
	rowJob   map[int32]*int32 // id → job
	imported map[int32]bool   // помеченные imported
	notes    []noteRec        // созданные заметки
	cleared  int64
}

type noteRec struct {
	projectID int32
	title     string
	createdBy int32
}

func newFakeStore() *fakeStore {
	return &fakeStore{rowProj: map[int32]int32{}, rowJob: map[int32]*int32{}, imported: map[int32]bool{}}
}

func (f *fakeStore) InsertLeaks(_ context.Context, rows []LeakInput) error {
	for _, r := range rows {
		f.seq++
		id := f.seq
		f.rowProj[id] = r.ProjectID
		f.rowJob[id] = r.JobID
		f.rows = append(f.rows, Leak{
			ID: id, Source: r.Source, Kind: r.Kind, Subject: r.Subject,
			Value: r.Value, Detail: r.Detail, Verified: r.Verified,
		})
	}
	return nil
}

func (f *fakeStore) filtered(projectID int32, ff Filter) []Leak {
	var out []Leak
	for _, l := range f.rows {
		if f.rowProj[l.ID] != projectID {
			continue
		}
		if ff.Source != nil && l.Source != *ff.Source {
			continue
		}
		if ff.JobID != nil {
			j := f.rowJob[l.ID]
			if j == nil || *j != *ff.JobID {
				continue
			}
		}
		l.Imported = f.imported[l.ID]
		out = append(out, l)
	}
	return out
}

func (f *fakeStore) ListLeaks(_ context.Context, projectID int32, ff Filter) ([]Leak, error) {
	return f.filtered(projectID, ff), nil
}
func (f *fakeStore) ListLeaksByIDs(_ context.Context, projectID int32, ids []int32) ([]Leak, error) {
	want := map[int32]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []Leak
	for _, l := range f.rows {
		if want[l.ID] && f.rowProj[l.ID] == projectID {
			l.Imported = f.imported[l.ID]
			out = append(out, l)
		}
	}
	return out, nil
}
func (f *fakeStore) MarkImported(_ context.Context, _ int32, ids []int32) error {
	for _, id := range ids {
		f.imported[id] = true
	}
	return nil
}
func (f *fakeStore) ClearLeaks(_ context.Context, projectID int32, ff Filter) (int64, error) {
	keep := f.rows[:0:0]
	var n int64
	for _, l := range f.rows {
		match := f.rowProj[l.ID] == projectID
		if ff.Source != nil && l.Source != *ff.Source {
			match = false
		}
		if match {
			n++
			continue
		}
		keep = append(keep, l)
	}
	f.rows = keep
	f.cleared += n
	return n, nil
}
func (f *fakeStore) ImportLeakNote(_ context.Context, projectID int32, title, _ string, createdBy int32) error {
	f.notes = append(f.notes, noteRec{projectID: projectID, title: title, createdBy: createdBy})
	return nil
}

func ptr[T any](v T) *T { return &v }

func seedTwo(t *testing.T, svc *Service, jobID int32) {
	t.Helper()
	err := svc.RecordLeaks(context.Background(), []LeakInput{
		{ProjectID: 7, JobID: &jobID, Source: SourceGithub, Kind: KindSecret, Subject: ptr("owner/repo"), Value: ptr("AKIA"), Detail: []byte(`{"detector":"AWS"}`), Verified: true},
		{ProjectID: 7, JobID: &jobID, Source: SourceGithub, Kind: KindSecret, Subject: ptr("owner/repo"), Value: ptr("tok"), Verified: false},
	})
	if err != nil {
		t.Fatalf("RecordLeaks: %v", err)
	}
}

// Report агрегирует total/verified/imported/by_source по всем источникам.
func TestReport_Summary(t *testing.T) {
	fs := newFakeStore()
	svc := NewService(fs)
	seedTwo(t, svc, 1)
	// вторая утечка из другого источника
	_ = svc.RecordLeaks(context.Background(), []LeakInput{{ProjectID: 7, Source: SourceHIBP, Kind: KindCredential, Subject: ptr("a@b.com")}})

	rep, err := svc.Report(context.Background(), 7, Filter{})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if rep.Summary.Total != 3 || rep.Summary.Verified != 1 {
		t.Fatalf("summary: %+v", rep.Summary)
	}
	if rep.Summary.BySource[SourceGithub] != 2 || rep.Summary.BySource[SourceHIBP] != 1 {
		t.Fatalf("by_source: %+v", rep.Summary.BySource)
	}
	if len(rep.Leaks) != 3 {
		t.Fatalf("expected 3 leaks, got %d", len(rep.Leaks))
	}
}

// Report с фильтром source отдаёт только его.
func TestReport_FilterBySource(t *testing.T) {
	fs := newFakeStore()
	svc := NewService(fs)
	seedTwo(t, svc, 1)
	_ = svc.RecordLeaks(context.Background(), []LeakInput{{ProjectID: 7, Source: SourceHIBP, Kind: KindCredential}})

	rep, err := svc.Report(context.Background(), 7, Filter{Source: ptr(SourceGithub)})
	if err != nil {
		t.Fatalf("Report: %v", err)
	}
	if rep.Summary.Total != 2 {
		t.Fatalf("expected 2 github leaks, got %d", rep.Summary.Total)
	}
}

// Import создаёт заметки и помечает выбранные imported (идемпотентно).
func TestImport_MarksImportedAndCreatesNotes(t *testing.T) {
	fs := newFakeStore()
	svc := NewService(fs)
	seedTwo(t, svc, 1)

	res, err := svc.Import(context.Background(), 7, 3, []int32{1, 2})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.Imported != 2 {
		t.Fatalf("expected 2 imported, got %d", res.Imported)
	}
	if len(fs.notes) != 2 {
		t.Fatalf("expected 2 notes created, got %d", len(fs.notes))
	}
	if !fs.imported[1] || !fs.imported[2] {
		t.Fatal("rows not marked imported")
	}
	// повторный импорт — идемпотентен (уже imported пропускаются)
	res2, err := svc.Import(context.Background(), 7, 3, []int32{1, 2})
	if err != nil {
		t.Fatalf("Import re-run: %v", err)
	}
	if res2.Imported != 0 {
		t.Fatalf("expected 0 on re-import, got %d", res2.Imported)
	}
	if len(fs.notes) != 2 {
		t.Fatalf("re-import must not create more notes, got %d", len(fs.notes))
	}
}

// Clear удаляет утечки проекта.
func TestClear(t *testing.T) {
	fs := newFakeStore()
	svc := NewService(fs)
	seedTwo(t, svc, 1)
	n, err := svc.Clear(context.Background(), 7, Filter{})
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 cleared, got %d", n)
	}
}
