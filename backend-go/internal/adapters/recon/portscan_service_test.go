package recon

import "testing"

const nmapServiceXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="9100"><state state="open"/><service name="jetdirect"/></port>
      <port protocol="tcp" portid="8080"><state state="closed"/><service name="http-proxy"/></port>
    </ports>
  </host>
</nmaprun>`

// nmap -sV → сервис и версия порта заполнены (пользователь хочет видеть 9100/tcp
// опознанным, а не «unknown»).
func TestParseNmapServicePorts_fillsServiceVersion(t *testing.T) {
	ports := ParseNmapServicePorts(nmapServiceXML)
	if len(ports) != 2 { // closed 8080 отброшен
		t.Fatalf("want 2 open ports, got %d: %+v", len(ports), ports)
	}
	if ports[0].Port != 80 || ports[1].Port != 9100 { // сорт по номеру порта
		t.Fatalf("ports not sorted: %+v", ports)
	}
	if ports[0].Service != "http" || ports[0].Version != "nginx 1.18.0" {
		t.Errorf("80 service/version = %q/%q, want http/nginx 1.18.0", ports[0].Service, ports[0].Version)
	}
	// сервис без product/version — имя есть, версия пустая (не «unknown»).
	if ports[1].Service != "jetdirect" || ports[1].Version != "" {
		t.Errorf("9100 service/version = %q/%q, want jetdirect/''", ports[1].Service, ports[1].Version)
	}
	if ports[1].Proto != "tcp" || ports[1].State != "open" {
		t.Errorf("9100 proto/state = %q/%q, want tcp/open", ports[1].Proto, ports[1].State)
	}
}

func TestParseNmapServicePorts_garbage(t *testing.T) {
	if got := ParseNmapServicePorts(""); len(got) != 0 {
		t.Errorf("empty XML should be empty, got %v", got)
	}
	if got := ParseNmapServicePorts("<broken"); len(got) != 0 {
		t.Errorf("broken XML should be empty, got %v", got)
	}
}

// port_scan_scope=="all" добавляет финальную -p- фазу; каждая фаза несёт -sV.
func TestNmapPhases_deepAddsFullScan(t *testing.T) {
	if got := len(NmapPhases(false)); got != 2 {
		t.Fatalf("shallow phases = %d, want 2", got)
	}
	deep := NmapPhases(true)
	if len(deep) != 3 || deep[2].Name != "full" {
		t.Fatalf("deep phases = %+v, want 3 ending in full (-p-)", deep)
	}
	for _, ph := range deep {
		found := false
		for _, a := range ph.Args {
			if a == "-sV" {
				found = true
			}
		}
		if !found {
			t.Errorf("phase %q missing -sV: %v", ph.Name, ph.Args)
		}
	}
}
