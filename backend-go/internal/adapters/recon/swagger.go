package recon

import (
	"context"
	"encoding/json"
	"strings"
	"time"
)

// Обнаружение Swagger/OpenAPI-спек как источник эндпоинтов стадии endpoints.
// В отличие от katana/gau/waybackurls работает НЕЗАВИСИМО от режима (passive/
// active): просто дёргает известные пути спек по каждому живому хосту, и если
// нашёл — вытаскивает все ручки (path + метод) прямо из документа. Так ферма
// находит API даже там, где нет ни архивов, ни ссылок на UI.

// swaggerPaths — типовые расположения спеки (Springfox/Swashbuckle/gin-swagger/
// FastAPI/Django REST/… и голые openapi.json). Пробуем как есть, без брута.
var swaggerPaths = []string{
	"/swagger.json",
	"/swagger/v1/swagger.json",
	"/swagger/doc.json",
	"/openapi.json",
	"/openapi/v1.json",
	"/v2/api-docs",
	"/v3/api-docs",
	"/api-docs",
	"/api-docs/swagger.json",
	"/api/swagger.json",
	"/api/openapi.json",
	"/api/v1/swagger.json",
	"/api/v2/swagger.json",
	"/api/v1/openapi.json",
	"/docs/swagger.json",
	"/swagger-ui/swagger.json",
	"/swagger-resources",
}

const (
	swaggerSpecCap     = 8 << 20 // 8 МБ на спеку — больше почти всегда мусор/не спека
	swaggerMaxPerHost  = 5000    // потолок ручек с одного хоста (защита от гигантских спек)
	swaggerReqTimeout  = 8 * time.Second
	swaggerMaxRedirect = 3
)

// SwaggerURLs пробует известные пути Swagger/OpenAPI по хосту (сначала https,
// потом http) и возвращает и саму спеку как URL, и вытащенные из неё ручки.
// Нет спеки / хост не отвечает → пусто (не ошибка), как остальные тулы стадии.
func SwaggerURLs(ctx context.Context, host string, s Settings) ([]EndpointHit, string) {
	if !safeHost(host) {
		return nil, ""
	}
	client := newGuardedClient(s, swaggerReqTimeout, true, swaggerMaxRedirect)
	defer client.CloseIdleConnections()

	var hits []EndpointHit
	seen := map[string]bool{}
	add := func(h EndpointHit) {
		if h.URL == "" || seen[h.URL] || len(hits) >= swaggerMaxPerHost {
			return
		}
		seen[h.URL] = true
		hits = append(hits, h)
	}

	for _, scheme := range []string{"https", "http"} {
		base := scheme + "://" + host
		for _, p := range swaggerPaths {
			if ctx.Err() != nil {
				return hits, ""
			}
			specURL := base + p
			ctype, body, status, _ := jsFetch(ctx, client, specURL, swaggerSpecCap)
			if status != "ok" || len(body) == 0 {
				continue
			}
			// Спека — это JSON (openapi/swagger). HTML swagger-ui пропускаем.
			if !strings.Contains(strings.ToLower(ctype), "json") && body[0] != '{' && body[0] != '[' {
				continue
			}
			eps := parseOpenAPIPaths(body, base)
			if len(eps) == 0 {
				continue
			}
			add(EndpointHit{URL: specURL, Source: "swagger"}) // сама спека — тоже находка
			for _, ep := range eps {
				add(ep)
			}
			if len(hits) >= swaggerMaxPerHost {
				return hits, ""
			}
		}
		// Нашли по https — по http не ходим (обычно тот же контент).
		if len(hits) > 0 {
			break
		}
	}
	return hits, ""
}

// parseOpenAPIPaths вытаскивает ручки из тела спеки: и Swagger 2.0 (basePath), и
// OpenAPI 3 (servers[].url). Для каждой пары path×method даёт EndpointHit с
// абсолютным URL и методом. Метод-ключи, не являющиеся HTTP-глаголами
// (parameters, summary…), игнорируются.
func parseOpenAPIPaths(body []byte, base string) []EndpointHit {
	var doc struct {
		BasePath string                                `json:"basePath"` // Swagger 2.0
		Servers  []struct{ URL string `json:"url"` }   `json:"servers"`  // OpenAPI 3
		Paths    map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(body, &doc); err != nil || len(doc.Paths) == 0 {
		return nil
	}
	// Префикс пути: OpenAPI3 servers[0].url (если относительный) либо Swagger2 basePath.
	prefix := strings.TrimRight(doc.BasePath, "/")
	root := base
	if len(doc.Servers) > 0 {
		su := strings.TrimSpace(doc.Servers[0].URL)
		switch {
		case strings.HasPrefix(su, "http://") || strings.HasPrefix(su, "https://"):
			root = strings.TrimRight(su, "/")
			prefix = ""
		case su != "" && su != "/":
			prefix = "/" + strings.Trim(su, "/")
		}
	}
	verbs := map[string]bool{"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true, "HEAD": true, "OPTIONS": true, "TRACE": true}
	var hits []EndpointHit
	for p, methods := range doc.Paths {
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		full := root + prefix + p
		var any bool
		for m := range methods {
			if mu := strings.ToUpper(m); verbs[mu] {
				hits = append(hits, EndpointHit{URL: full, Method: mu, Source: "swagger"})
				any = true
			}
		}
		if !any { // путь без явных методов — всё равно ручка
			hits = append(hits, EndpointHit{URL: full, Source: "swagger"})
		}
	}
	return hits
}
