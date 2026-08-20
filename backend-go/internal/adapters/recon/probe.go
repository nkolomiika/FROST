package recon

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
)

// ProbeResult — итог HTTP-пробива одного порта (порт core.ProbeResult).
type ProbeResult struct {
	Hostname   string
	Port       int
	Scheme     string
	Inferred   bool
	Responded  bool
	HTTPStatus *int
	Error      string
	Cloudflare bool
}

// Служебные заголовки Cloudflare — их наличие однозначно выдаёт CF-edge.
var cfHeaders = []string{"Cf-Ray", "Cf-Cache-Status", "Cf-Mitigated"}

// cfFromHeaders — CF прямо из ответа: server=cloudflare либо любой cf-* заголовок
// (порт _cf_from_headers).
func cfFromHeaders(h http.Header) bool {
	if strings.Contains(strings.ToLower(h.Get("Server")), "cloudflare") {
		return true
	}
	for _, name := range cfHeaders {
		if h.Get(name) != "" {
			return true
		}
	}
	return false
}

// guardedDialContext возвращает dial-функцию, которая ре-резолвит host и отклоняет
// приватные/внутренние IP на КАЖДОМ соединении (в т.ч. на редирект-хопе) — защита
// от DNS-rebinding между нашим резолвом и реальным подключением (порт ProbeTransport).
func guardedDialContext(s Settings) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if s.FarmAllowPrivate {
		return d.DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS не разрешает %s: %w", host, err)
		}
		var lastErr error
		blockedAll := true
		for _, ip := range ips {
			addrStr := ip.Unmap().String()
			if IsDisallowedIP(addrStr) {
				lastErr = fmt.Errorf("%s для %s запрещён (SSRF)", addrStr, host)
				continue
			}
			blockedAll = false
			conn, derr := d.DialContext(ctx, network, net.JoinHostPort(addrStr, port))
			if derr == nil {
				return conn, nil
			}
			lastErr = derr
		}
		if blockedAll && lastErr == nil {
			lastErr = fmt.Errorf("%s: все адреса запрещены (SSRF)", host)
		}
		return nil, lastErr
	}
}

// newGuardedClient — http.Client с SSRF-гейтом на dial и отключённой проверкой TLS
// (пентест-цели часто с self-signed). follow=false → редиректы не идём (пробив);
// follow=true с maxRedirects — для скачивания JS (каждый хоп ре-гейтится dial'ом).
func newGuardedClient(s Settings, timeout time.Duration, follow bool, maxRedirects int) *http.Client {
	tr := &http.Transport{
		DialContext:         guardedDialContext(s),
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec — пентест-цели с self-signed TLS
		MaxIdleConns:        s.maxConcurrency(),
		MaxIdleConnsPerHost: s.maxConcurrency(),
		ForceAttemptHTTP2:   true,
	}
	client := &http.Client{Transport: tr, Timeout: timeout}
	if !follow {
		client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	} else {
		client.CheckRedirect = func(_ *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		}
	}
	return client
}

// ProbeCandidates — HTTP-пробив кандидатов до корня «/». БД не трогает (порт
// probe_candidates). follow_redirects=false: 301 пишем как 301, а не идём по нему.
func ProbeCandidates(ctx context.Context, candidates []ProbeCandidate, s Settings) []ProbeResult {
	if len(candidates) == 0 {
		return nil
	}
	client := newGuardedClient(s, s.FarmProbeTimeout, false, 0)
	defer client.CloseIdleConnections()

	results := make([]ProbeResult, len(candidates))
	var eg errgroup.Group
	eg.SetLimit(s.maxConcurrency())
	for i, c := range candidates {
		i, c := i, c
		eg.Go(func() error {
			results[i] = probeOne(ctx, client, c)
			return nil
		})
	}
	_ = eg.Wait()
	return results
}

func probeOne(ctx context.Context, client *http.Client, c ProbeCandidate) ProbeResult {
	host := c.Hostname
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	url := fmt.Sprintf("%s://%s:%d/", c.Scheme, host, c.Port)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ProbeResult{Hostname: c.Hostname, Port: c.Port, Scheme: c.Scheme, Inferred: c.Inferred, Responded: false, Error: errName(err)}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{Hostname: c.Hostname, Port: c.Port, Scheme: c.Scheme, Inferred: c.Inferred, Responded: false, Error: errName(err)}
	}
	defer resp.Body.Close()
	status := resp.StatusCode
	return ProbeResult{
		Hostname:   c.Hostname,
		Port:       c.Port,
		Scheme:     c.Scheme,
		Inferred:   c.Inferred,
		Responded:  true,
		HTTPStatus: &status,
		Cloudflare: cfFromHeaders(resp.Header),
	}
}

// ErrLabel — краткая метка ошибки для per-element errors (аналог type(exc).__name__).
func ErrLabel(err error) string { return errName(err) }

// errName — краткая метка ошибки (аналог Python type(exc).__name__ в error-поле).
func errName(err error) string {
	if err == nil {
		return ""
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "Timeout"
	}
	msg := err.Error()
	if len(msg) > 80 {
		msg = msg[:80]
	}
	return msg
}
