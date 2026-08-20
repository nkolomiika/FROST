package recon

import (
	"net/http"
	"testing"
)

// CF по заголовкам ответа пробива — независимо от внешнего движка детекта (порт _cf_from_headers).

func TestCFFromHeaders_serverHeader(t *testing.T) {
	if !cfFromHeaders(http.Header{"Server": {"cloudflare"}}) {
		t.Errorf("server=cloudflare should be CF")
	}
	if !cfFromHeaders(http.Header{"Server": {"Cloudflare"}}) { // регистр не важен
		t.Errorf("server=Cloudflare should be CF")
	}
}

func TestCFFromHeaders_cfRayHeader(t *testing.T) {
	// BYOIP вроде claude.com: server может быть иным, но cf-ray выдаёт CF-edge.
	if !cfFromHeaders(http.Header{"Cf-Ray": {"a1dce7b1-VNO"}}) {
		t.Errorf("cf-ray should be CF")
	}
	if !cfFromHeaders(http.Header{"Cf-Cache-Status": {"DYNAMIC"}}) {
		t.Errorf("cf-cache-status should be CF")
	}
}

func TestCFFromHeaders_noCF(t *testing.T) {
	if cfFromHeaders(http.Header{"Server": {"nginx"}}) {
		t.Errorf("server=nginx should NOT be CF")
	}
	if cfFromHeaders(http.Header{}) {
		t.Errorf("no headers should NOT be CF")
	}
}
