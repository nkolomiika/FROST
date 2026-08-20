package vulns

import (
	"regexp"
	"strings"

	"github.com/nkolomiika/frost/internal/adapters/cvss"
	"github.com/nkolomiika/frost/internal/apperr"
)

// cvssPrefixRe — ведущий префикс версии CVSS (порт re.sub(r"^CVSS:\d\.\d/")).
var cvssPrefixRe = regexp.MustCompile(`^CVSS:\d\.\d/`)

// truthy — *string считается «истинным», если он не nil и не пустой (порт python-falsy).
func truthy(p *string) bool { return p != nil && *p != "" }

// truthyAny — значение payload считается «истинным», если оно не nil и (если строка) непустое.
func truthyAny(v any) bool {
	if v == nil {
		return false
	}
	if s, ok := v.(string); ok {
		return s != ""
	}
	return true
}

// asStrPtr — значение payload (string|nil) → *string.
func asStrPtr(v any) *string {
	if v == nil {
		return nil
	}
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

// normalizeCvssVector — порт _normalize_cvss_vector: приводит вектор к префиксу
// CVSS:{version}/… (заменяет ведущий CVSS:\d.\d/ либо добавляет свой).
func normalizeCvssVector(version, vector *string) *string {
	if !truthy(version) || !truthy(vector) {
		return nil
	}
	versionValue := *version
	raw := strings.TrimSpace(*vector)
	if raw == "" {
		return nil
	}
	normalized := cvssPrefixRe.ReplaceAllString(raw, "CVSS:"+versionValue+"/")
	if !strings.HasPrefix(normalized, "CVSS:") {
		normalized = "CVSS:" + versionValue + "/" + strings.TrimLeft(normalized, "/")
	}
	return &normalized
}

// calculateCvssScore — порт _calculate_cvss_score: поддерживается только CVSS 4.0.
// Возвращает нормализованный вектор и рассчитанный балл. Ошибки cvss-пакета и
// неподдерживаемую версию оборачивает как ValidationError (как в Python — оба
// случая заворачиваются в «Некорректный CVSS вектор: …»).
func calculateCvssScore(version, vector *string) (*string, *float64, error) {
	normalized := normalizeCvssVector(version, vector)
	if normalized == nil {
		return nil, nil, nil
	}
	versionValue := ""
	if version != nil {
		versionValue = *version
	}
	if versionValue != "4.0" {
		return nil, nil, apperr.Validation("Некорректный CVSS вектор: Поддерживается только CVSS 4.0")
	}
	score, err := cvss.Score(*normalized)
	if err != nil {
		return nil, nil, apperr.Validation("Некорректный CVSS вектор: " + err.Error())
	}
	s := score
	return normalized, &s, nil
}

// applyCalculatedCvssFields — порт _apply_calculated_cvss_fields. Мутирует payload
// (ключи cvss_version/cvss_vector/cvss_score), повторяя ветвление Python:
// явная очистка вектора vs присутствие вектора vs явный балл vs только версия.
func applyCalculatedCvssFields(payload map[string]any, currentVersion, currentVector *string) error {
	scoreVal, scorePresent := payload["cvss_score"]
	hasExplicitScore := scorePresent && scoreVal != nil

	nextVersion := currentVersion
	if v, ok := payload["cvss_version"]; ok {
		nextVersion = asStrPtr(v)
	}
	nextVector := currentVector
	if v, ok := payload["cvss_vector"]; ok {
		nextVector = asStrPtr(v)
	}

	// Явная очистка: вектор прислан пустым/null.
	if v, ok := payload["cvss_vector"]; ok && !truthyAny(v) {
		if hasExplicitScore {
			return apperr.Validation("CVSS score рассчитывается автоматически и требует корректный CVSS 4.0 вектор")
		}
		payload["cvss_version"] = nil
		payload["cvss_vector"] = nil
		payload["cvss_score"] = nil
		return nil
	}

	// Есть вектор — считаем балл (версия обязательна).
	if truthy(nextVector) {
		if !truthy(nextVersion) {
			return apperr.Validation("Для расчёта CVSS укажите версию 4.0 и корректный вектор")
		}
		normalized, score, err := calculateCvssScore(nextVersion, nextVector)
		if err != nil {
			return err
		}
		payload["cvss_version"] = *nextVersion
		if normalized != nil {
			payload["cvss_vector"] = *normalized
		} else {
			payload["cvss_vector"] = nil
		}
		if score != nil {
			payload["cvss_score"] = *score
		} else {
			payload["cvss_score"] = nil
		}
		return nil
	}

	if hasExplicitScore {
		return apperr.Validation("CVSS score рассчитывается автоматически и требует корректный CVSS 4.0 вектор")
	}
	if v, ok := payload["cvss_version"]; ok && truthyAny(v) {
		return apperr.Validation("Для расчёта CVSS укажите корректный CVSS 4.0 вектор")
	}
	return nil
}

// severityFromCvssScore — порт _severity_from_cvss_score (FROST-полосы). Значение —
// в БД-регистре (UPPERCASE).
func severityFromCvssScore(score *float64) string {
	if score == nil {
		return SeverityInfo
	}
	s := *score
	switch {
	case s >= 9.0:
		return SeverityCritical
	case s >= 7.0:
		return SeverityHigh
	case s >= 4.0:
		return SeverityMedium
	case s > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}
