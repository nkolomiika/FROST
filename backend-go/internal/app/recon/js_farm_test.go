package recon

import (
	"context"
	"reflect"
	"testing"

	reconnet "github.com/nkolomiika/frost/internal/adapters/recon"
	"github.com/nkolomiika/frost/internal/apperr"
)

// Порт backend/tests/test_js_farm_service.py. Фазы discover/download/scan и
// build_archive живут в adapters/recon (DiscoverAndScan/BuildJSArchive) без
// transport-сейма — сетевые, вне юнит-scope. Здесь: выбор доменов, parse_raw,
// wiring persist и guard пустого архива.

func TestJSDomains_onlyNamedHostOrigin(t *testing.T) {
	// origin=host отфильтрован БД; здесь дублирование, IP-литерал и пустое имя
	// выкидываются в самом сервисе.
	store := &stubStore{domainHostnames: []string{"acme.com", "acme.com", "1.2.3.4", "", "api.acme.com"}}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})

	got, err := svc.jsDomains(context.Background(), 7, "")
	if err != nil {
		t.Fatalf("jsDomains: %v", err)
	}
	want := []string{"acme.com", "api.acme.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("jsDomains = %v, want %v", got, want)
	}
}

func TestParseRawDomains_dedupsAndLowercases(t *testing.T) {
	got := parseRawDomains("Acme.com\n api.acme.com \nacme.com\n")
	want := []string{"acme.com", "api.acme.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseRawDomains = %v, want %v", got, want)
	}
}

func TestPersistJS_createsFileAndSecrets(t *testing.T) {
	store := &stubStore{originHostMap: map[string]int32{"acme.com": 5}}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	size := int32(len("body"))
	files := []reconnet.ScannedFile{{
		URL: "https://acme.com/static/app.bundle.js", Hostname: "acme.com", Status: "ok",
		SHA256: "abc", SizeBytes: &size, ContentType: "application/javascript",
		Secrets:   []reconnet.Secret{{Kind: "aws_access_key"}},
		Endpoints: []string{"/api/v1/secret-data", "/admin/panel"},
	}}

	res, err := svc.persistJS(context.Background(), 101, 7, files, nil)
	if err != nil {
		t.Fatalf("persistJS: %v", err)
	}
	if res.FilesScanned != 1 || res.SecretsFound != 1 || res.EndpointsFound != 2 || res.DomainsScanned != 1 {
		t.Errorf("counters = scanned %d secrets %d endpoints %d domains %d, want 1/1/2/1",
			res.FilesScanned, res.SecretsFound, res.EndpointsFound, res.DomainsScanned)
	}
	if len(store.jsFiles) != 1 {
		t.Fatalf("want 1 persisted js file, got %d", len(store.jsFiles))
	}
	f := store.jsFiles[0]
	if f.HostID != 5 || f.SecretCount != 1 || f.EndpointCount != 2 {
		t.Errorf("js file input = host %d secrets %d endpoints %d, want 5/1/2", f.HostID, f.SecretCount, f.EndpointCount)
	}
	if store.auditCount != 1 {
		t.Errorf("audit count = %d, want 1", store.auditCount)
	}
}

func TestPersistJS_reportsMissingHost(t *testing.T) {
	store := &stubStore{originHostMap: map[string]int32{}} // хостов нет
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	files := []reconnet.ScannedFile{{URL: "https://acme.com/app.js", Hostname: "acme.com", Status: "ok"}}

	res, err := svc.persistJS(context.Background(), 101, 7, files, nil)
	if err != nil {
		t.Fatalf("persistJS: %v", err)
	}
	if res.FilesScanned != 0 {
		t.Errorf("files_scanned = %d, want 0", res.FilesScanned)
	}
	found := false
	for _, e := range res.Errors {
		if e == "acme.com: хост не найден" {
			found = true
		}
	}
	if !found {
		t.Errorf("want 'хост не найден' error, got %v", res.Errors)
	}
}

func TestBuildArchive_raisesWithoutFiles(t *testing.T) {
	store := &stubStore{jsFileURLs: nil}
	svc := stubService(store, reconnet.Settings{}, Config{MaxAttempts: 3})
	hostID := int32(5)

	_, _, err := svc.BuildArchive(context.Background(), 101, &hostID)
	if err == nil {
		t.Fatal("want NotFound error when no js files")
	}
	ae, ok := err.(*apperr.Error)
	if !ok || ae.Kind != apperr.KindNotFound {
		t.Errorf("err = %v, want *apperr.Error KindNotFound", err)
	}
}
