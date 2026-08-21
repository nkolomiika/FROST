package http

import (
	"encoding/json"
	"time"

	"github.com/nkolomiika/frost/internal/app/recon"
)

// reconJobResponse — единый ответ *FarmJobOut/*JobOut (result уже готовый JSON).
type reconJobResponse struct {
	ID           int32           `json:"id"`
	ProjectID    int32           `json:"project_id"`
	Kind         string          `json:"kind"`
	Status       string          `json:"status"`
	TargetsTotal *int32          `json:"targets_total"`
	Result       json.RawMessage `json:"result"`
	Error        *string         `json:"error"`
	CreatedAt    time.Time       `json:"created_at"`
}

func jobResponse(v recon.JobView) reconJobResponse {
	return reconJobResponse{
		ID:           v.ID,
		ProjectID:    v.ProjectID,
		Kind:         v.Kind,
		Status:       v.Status,
		TargetsTotal: v.TargetsTotal,
		Result:       json.RawMessage(v.Result),
		Error:        v.Error,
		CreatedAt:    v.CreatedAt,
	}
}

// farmRunResponse — статус+прогресс полного прогона фермы. progress уже готовый
// JSON снимка RunProgress (snake_case), result — итог FarmRunResult (по done).
type farmRunResponse struct {
	ID           int32           `json:"id"`
	ProjectID    int32           `json:"project_id"`
	Kind         string          `json:"kind"`
	Status       string          `json:"status"`
	TargetsTotal *int32          `json:"targets_total"`
	Progress     json.RawMessage `json:"progress"`
	Result       json.RawMessage `json:"result"`
	Error        *string         `json:"error"`
	CreatedAt    time.Time       `json:"created_at"`
}

func farmRunResp(v recon.JobView) farmRunResponse {
	return farmRunResponse{
		ID:           v.ID,
		ProjectID:    v.ProjectID,
		Kind:         v.Kind,
		Status:       v.Status,
		TargetsTotal: v.TargetsTotal,
		Progress:     json.RawMessage(v.Progress),
		Result:       json.RawMessage(v.Result),
		Error:        v.Error,
		CreatedAt:    v.CreatedAt,
	}
}

// jsSecretResponse — JsSecretOut.
type jsSecretResponse struct {
	Kind         string  `json:"kind"`
	MatchPreview string  `json:"match_preview"`
	Snippet      *string `json:"snippet"`
	Severity     string  `json:"severity"`
}

// jsFileResponse — JsFileOut.
type jsFileResponse struct {
	ID            int32              `json:"id"`
	HostID        int32              `json:"host_id"`
	Hostname      *string            `json:"hostname"`
	URL           string             `json:"url"`
	Status        string             `json:"status"`
	SizeBytes     *int32             `json:"size_bytes"`
	ContentType   *string            `json:"content_type"`
	SecretCount   int32              `json:"secret_count"`
	EndpointCount int32              `json:"endpoint_count"`
	Endpoints     []string           `json:"endpoints"`
	Secrets       []jsSecretResponse `json:"secrets"`
	FetchedAt     *time.Time         `json:"fetched_at"`
}

func jsFileResponses(files []recon.JSFileView) []jsFileResponse {
	out := make([]jsFileResponse, 0, len(files))
	for _, f := range files {
		secrets := make([]jsSecretResponse, 0, len(f.Secrets))
		for _, s := range f.Secrets {
			snippet := s.Snippet
			var sp *string
			if snippet != "" {
				sp = &snippet
			}
			secrets = append(secrets, jsSecretResponse{Kind: s.Kind, MatchPreview: s.MatchPreview, Snippet: sp, Severity: s.Severity})
		}
		endpoints := f.Endpoints
		if endpoints == nil {
			endpoints = []string{}
		}
		out = append(out, jsFileResponse{
			ID: f.ID, HostID: f.HostID, Hostname: f.Hostname, URL: f.URL, Status: f.Status,
			SizeBytes: f.SizeBytes, ContentType: f.ContentType, SecretCount: f.SecretCount,
			EndpointCount: f.EndpointCount, Endpoints: endpoints, Secrets: secrets, FetchedAt: f.FetchedAt,
		})
	}
	return out
}
