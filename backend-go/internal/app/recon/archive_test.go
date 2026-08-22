package recon

import (
	"reflect"
	"testing"
)

func sp(s string) *string { return &s }

// Круговой прогон gzip-снимка стейджинга: то, что архивируем, должно вернуться из
// MinIO байт-в-байт (иначе регидрация теряет данные — а это удаление из БД).
func TestStagingBlobRoundTrip(t *testing.T) {
	in := stagingArchiveBlob{
		JobID:     42,
		ProjectID: 7,
		Hosts: []StagedHost{
			{ID: 1, Hostname: "a.example.com", IP: sp("1.2.3.4"), Alive: true, Source: "subfinder", Imported: false,
				Ports: []StagedPort{{Port: 443, Proto: "tcp", State: "open", Service: sp("https"), Version: sp("nginx")}}},
			{ID: 2, Hostname: "b.example.com", Alive: false, Source: "crtsh"},
		},
		Endpoints: []StagedEndpoint{
			{ID: 3, Host: "a.example.com", URL: "https://a.example.com/api", Method: sp("GET"), Source: "katana"},
		},
		Js: []StagedJs{
			{ID: 4, Host: "a.example.com", URL: "https://a.example.com/app.js", Kind: "secret", Value: "AKIA…", Severity: sp("high")},
		},
	}
	data, err := gzipStagingBlob(in)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	out, err := gunzipStagingBlob(data)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round-trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
}

// Конвертеры List→Input сохраняют все значимые поля (иначе восстановленные строки
// беднее исходных). Проверяем именно перенос данных + проставление project/job.
func TestStagedConvertersPreserveFields(t *testing.T) {
	hosts := stagedHostsToInputs(7, 42, []StagedHost{
		{ID: 9, Hostname: "h", IP: sp("9.9.9.9"), Alive: true, Source: "src", Imported: true,
			Ports: []StagedPort{{Port: 80, State: "open"}}},
	})
	if len(hosts) != 1 {
		t.Fatalf("hosts len %d", len(hosts))
	}
	h := hosts[0]
	if h.ProjectID != 7 || h.JobID != 42 || h.Hostname != "h" || h.IP == nil || *h.IP != "9.9.9.9" || !h.Alive || h.Source != "src" || len(h.Ports) != 1 {
		t.Fatalf("host input not preserved: %+v", h)
	}

	eps := stagedEndpointsToInputs(7, 42, []StagedEndpoint{{Host: "h", URL: "u", Method: sp("POST"), Source: "katana"}})
	if len(eps) != 1 || eps[0].ProjectID != 7 || eps[0].JobID != 42 || eps[0].URL != "u" || eps[0].Method == nil || *eps[0].Method != "POST" {
		t.Fatalf("endpoint input not preserved: %+v", eps)
	}

	js := stagedJsToInputs(7, 42, []StagedJs{{Host: "h", URL: "u", Kind: "secret", Value: "v", Severity: sp("low")}})
	if len(js) != 1 || js[0].ProjectID != 7 || js[0].JobID != 42 || js[0].Kind != "secret" || js[0].Value != "v" || js[0].Severity == nil || *js[0].Severity != "low" {
		t.Fatalf("js input not preserved: %+v", js)
	}
}
