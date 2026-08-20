// Package report — генерация Word-отчётов через Python-sidecar (интерим Go-миграции).
// Go собирает данные проекта (sqlc + MinIO) и шлёт их в sidecar (app/report_sidecar.py),
// который переиспользует проверенный word_builder и возвращает .docx. Финальная цель —
// порт word_builder на Go; sidecar снимает риск байт-точности сертификационных документов.
package report

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nkolomiika/frost/internal/apperr"
)

// Kind — тип отчёта.
type Kind string

const (
	KindSZI Kind = "szi"
	KindPP  Kind = "pp"
)

// Collected — сырые данные проекта для отчёта (собирает Store).
type Collected struct {
	ProjectName     string
	StartDate       *string // ISO YYYY-MM-DD
	EndDate         *string
	Members         []string
	Hosts           []HostJSON
	Vulnerabilities []VulnJSON
	Assets          []AssetJSON
	ImageFiles      []ImageFile // файлы-картинки (для докачки из MinIO)
	Files           []FileJSON  // метаданные всех файлов (для sidecar)
}

// ImageFile — картинка-вложение, которую надо докачать из MinIO.
type ImageFile struct {
	ID       int32
	MinioKey string
}

// ── JSON-контракт с sidecar ──

type HostJSON struct {
	ID        int32   `json:"id"`
	Hostname  *string `json:"hostname"`
	IPAddress *string `json:"ip_address"`
}

type VulnJSON struct {
	ID               int32           `json:"id"`
	Title            string          `json:"title"`
	Severity         string          `json:"severity"`     // DB-имя (UPPERCASE)
	CvssVersion      *string         `json:"cvss_version"` // "V40"/"V31"/null
	CvssVector       *string         `json:"cvss_vector"`
	CvssScore        *float64        `json:"cvss_score"`
	CweID            *string         `json:"cwe_id"`
	Description      *string         `json:"description"`
	Impact           *string         `json:"impact"`
	Recommendations  *string         `json:"recommendations"`
	StepsToReproduce *string         `json:"steps_to_reproduce"`
	WorkflowSteps    json.RawMessage `json:"workflow_steps"` // JSON-массив или null
	Status           string          `json:"status"`
	CreatedBy        int32           `json:"created_by"`
}

type AssetJSON struct {
	ID              int32  `json:"id"`
	VulnerabilityID int32  `json:"vulnerability_id"`
	AssetType       string `json:"asset_type"` // DB-имя (UPPERCASE)
	AssetID         int32  `json:"asset_id"`
}

type FileJSON struct {
	ID              int32  `json:"id"`
	VulnerabilityID int32  `json:"vulnerability_id"`
	ContentType     string `json:"content_type"`
	OriginalName    string `json:"original_name"`
}

type bundle struct {
	Project         projectJSON       `json:"project"`
	Hosts           []HostJSON        `json:"hosts"`
	Ports           []any             `json:"ports"`
	Vulnerabilities []VulnJSON        `json:"vulnerabilities"`
	Assets          []AssetJSON       `json:"assets"`
	Files           []FileJSON        `json:"files"`
	Images          map[string]string `json:"images"`
	Members         []string          `json:"members"`
}

type projectJSON struct {
	Name      string  `json:"name"`
	StartDate *string `json:"start_date"`
	EndDate   *string `json:"end_date"`
}

// Store — порт сбора данных отчёта (реализуется reportrepo поверх sqlc).
type Store interface {
	Collect(ctx context.Context, projectID int32) (*Collected, error)
}

// Storage — порт объектного хранилища (докачка картинок).
type Storage interface {
	Get(ctx context.Context, key string) ([]byte, string, error)
}

// Service — сбор данных + вызов sidecar.
type Service struct {
	store      Store
	storage    Storage
	sidecarURL string
	token      string
	client     *http.Client
}

// NewService собирает сервис отчётов.
func NewService(store Store, storage Storage, sidecarURL, token string) *Service {
	return &Service{
		store: store, storage: storage, sidecarURL: sidecarURL, token: token,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

// Generate собирает отчёт указанного типа и возвращает .docx-байты и имя проекта.
func (s *Service) Generate(ctx context.Context, projectID int32, kind Kind) ([]byte, string, error) {
	col, err := s.store.Collect(ctx, projectID)
	if err != nil {
		return nil, "", err
	}
	images := map[string]string{}
	for _, f := range col.ImageFiles {
		data, _, err := s.storage.Get(ctx, f.MinioKey)
		if err != nil {
			continue // недоступную картинку пропускаем (как Python)
		}
		images[fmt.Sprint(f.ID)] = base64.StdEncoding.EncodeToString(data)
	}
	if col.Hosts == nil {
		col.Hosts = []HostJSON{}
	}
	if col.Vulnerabilities == nil {
		col.Vulnerabilities = []VulnJSON{}
	}
	if col.Assets == nil {
		col.Assets = []AssetJSON{}
	}
	if col.Files == nil {
		col.Files = []FileJSON{}
	}
	if col.Members == nil {
		col.Members = []string{}
	}
	b := bundle{
		Project:         projectJSON{Name: col.ProjectName, StartDate: col.StartDate, EndDate: col.EndDate},
		Hosts:           col.Hosts,
		Ports:           []any{},
		Vulnerabilities: col.Vulnerabilities,
		Assets:          col.Assets,
		Files:           col.Files,
		Images:          images,
		Members:         col.Members,
	}
	payload, err := json.Marshal(b)
	if err != nil {
		return nil, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.sidecarURL+"/render/"+string(kind), bytes.NewReader(payload))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("X-Sidecar-Token", s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", apperr.Newf(apperr.KindInternal, "reports sidecar недоступен: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, "", apperr.Newf(apperr.KindInternal, "reports sidecar вернул %d: %s", resp.StatusCode, string(body))
	}
	return body, col.ProjectName, nil
}
