package report

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Порт test_report_service.py к Go-шву отчётов.
//
// В Python ReportService._normalize_report_image_bytes перекодировал картинки
// через Pillow. В Go перекодирование ушло в Python-sidecar (см. report.go): Go
// лишь собирает данные проекта и упаковывает bundle (nil-срезы → [], картинки →
// base64), поэтому здесь проверяется именно сборка bundle и обработка картинок —
// единственный юнит-тестируемый шов на стороне Go. Сам _normalize_report_image_bytes
// на Go не портируется (нормализация байтов живёт в Python-sidecar).

type fakeStore struct {
	col *Collected
	err error
}

func (f *fakeStore) Collect(ctx context.Context, projectID int32) (*Collected, error) {
	return f.col, f.err
}

type fakeStorage struct {
	data map[string][]byte // ключ MinIO → байты
	err  error
}

func (f *fakeStorage) Get(ctx context.Context, key string) ([]byte, string, error) {
	if f.err != nil {
		return nil, "", f.err
	}
	b, ok := f.data[key]
	if !ok {
		return nil, "", errors.New("not found")
	}
	return b, "image/png", nil
}

// sidecarCapture поднимает фейковый sidecar, ловит присланный bundle и отдаёт docx.
func sidecarCapture(t *testing.T, captured *bundle) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, captured); err != nil {
			t.Errorf("sidecar received invalid bundle JSON: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PK-docx-bytes"))
	}))
}

// Nil-срезы коалесцируются в пустые JSON-массивы, а картинка попадает в bundle как
// base64. Возвращённые байты — это ответ sidecar, имя — имя проекта.
func TestGenerateBuildsBundleAndImages(t *testing.T) {
	imgBytes := []byte("\x89PNG-fake-image")
	store := &fakeStore{col: &Collected{
		ProjectName: "DemoApp",
		// Hosts/Vulnerabilities/Assets/Files/Members намеренно nil — проверяем коалесценцию.
		ImageFiles: []ImageFile{{ID: 11, MinioKey: "vuln/11.png"}},
	}}
	storage := &fakeStorage{data: map[string][]byte{"vuln/11.png": imgBytes}}

	var got bundle
	srv := sidecarCapture(t, &got)
	defer srv.Close()

	svc := NewService(store, storage, srv.URL, "")
	out, name, err := svc.Generate(context.Background(), 1, KindSZI)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if string(out) != "PK-docx-bytes" {
		t.Errorf("out = %q, want sidecar body", out)
	}
	if name != "DemoApp" {
		t.Errorf("name = %q, want DemoApp", name)
	}

	// nil-срезы → пустые (не null) массивы.
	if got.Hosts == nil || got.Vulnerabilities == nil || got.Assets == nil ||
		got.Files == nil || got.Members == nil {
		t.Errorf("nil slices not coalesced to []: %+v", got)
	}
	if got.Project.Name != "DemoApp" {
		t.Errorf("project.name = %q", got.Project.Name)
	}
	// Картинка упакована как base64 под строковым ключом ID.
	wantB64 := base64.StdEncoding.EncodeToString(imgBytes)
	if got.Images["11"] != wantB64 {
		t.Errorf("images[11] = %q, want base64 of image", got.Images["11"])
	}
}

// Недоступную из хранилища картинку сборка пропускает (как Python пропускал
// невалидный payload в _normalize_report_image_bytes → None).
func TestGenerateSkipsUnavailableImage(t *testing.T) {
	store := &fakeStore{col: &Collected{
		ProjectName: "DemoApp",
		ImageFiles:  []ImageFile{{ID: 11, MinioKey: "missing.png"}},
	}}
	storage := &fakeStorage{err: errors.New("minio down")}

	var got bundle
	srv := sidecarCapture(t, &got)
	defer srv.Close()

	svc := NewService(store, storage, srv.URL, "")
	if _, _, err := svc.Generate(context.Background(), 1, KindPP); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(got.Images) != 0 {
		t.Errorf("images = %v, want empty (unavailable image skipped)", got.Images)
	}
}

// Ошибка сбора данных пробрасывается наружу без вызова sidecar.
func TestGeneratePropagatesCollectError(t *testing.T) {
	store := &fakeStore{err: errors.New("collect failed")}
	svc := NewService(store, &fakeStorage{}, "http://unused.invalid", "")

	if _, _, err := svc.Generate(context.Background(), 1, KindSZI); err == nil {
		t.Fatal("expected Collect error to propagate")
	}
}

// Ненулевой статус sidecar превращается в ошибку.
func TestGenerateSidecarError(t *testing.T) {
	store := &fakeStore{col: &Collected{ProjectName: "DemoApp"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	svc := NewService(store, &fakeStorage{}, srv.URL, "")
	if _, _, err := svc.Generate(context.Background(), 1, KindSZI); err == nil {
		t.Fatal("expected sidecar 500 to become an error")
	}
}
