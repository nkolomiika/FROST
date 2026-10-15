package jira

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nkolomiika/frost/internal/app/tasks"
	"github.com/nkolomiika/frost/internal/apperr"
)

func newTestClient(url string) *Client {
	return New(Config{BaseURL: url, Token: "tok", ProjectKey: "STS", APIVersion: "2", MaxResults: 100})
}

func TestList_MappingAndJQL(t *testing.T) {
	var gotJQL, gotStart, gotMax string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/2/search" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("bad auth header: %q", r.Header.Get("Authorization"))
		}
		gotJQL = r.URL.Query().Get("jql")
		gotStart = r.URL.Query().Get("startAt")
		gotMax = r.URL.Query().Get("maxResults")
		_, _ = w.Write([]byte(`{
			"total": 2,
			"issues": [
				{"key":"STS-5","fields":{"summary":"Login bug","updated":"2026-01-02T10:00:00.000+0000","created":"2026-01-01T09:00:00.000+0000",
					"status":{"name":"In Progress","statusCategory":{"key":"indeterminate"}},
					"issuetype":{"name":"Bug"},"priority":{"name":"High"},"assignee":{"displayName":"Alice"}}},
				{"key":"STS-6","fields":{"summary":"Done task","status":{"name":"Closed","statusCategory":{"key":"done"}}}}
			]
		}`))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL)
	items, total, err := c.List(context.Background(), tasks.ListParams{Query: "login", Category: tasks.CategoryInProgress, Page: 2, Size: 10})
	if err != nil {
		t.Fatalf("List err: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("total=%d items=%d", total, len(items))
	}
	if items[0].Key != "STS-5" || items[0].Status != "In Progress" || items[0].StatusCategory != tasks.CategoryInProgress {
		t.Errorf("issue0 mapped wrong: %+v", items[0])
	}
	if items[0].IssueType != "Bug" || items[0].Priority != "High" || items[0].Assignee != "Alice" {
		t.Errorf("issue0 fields wrong: %+v", items[0])
	}
	if items[1].StatusCategory != tasks.CategoryDone {
		t.Errorf("issue1 category = %q, want done", items[1].StatusCategory)
	}
	// JQL expectations
	for _, want := range []string{`project = "STS"`, `summary ~ "login*"`, `statusCategory = "In Progress"`, "ORDER BY updated DESC"} {
		if !strings.Contains(gotJQL, want) {
			t.Errorf("JQL missing %q; got %q", want, gotJQL)
		}
	}
	if strings.Contains(gotJQL, "key =") {
		t.Errorf("text query must not add key clause; got %q", gotJQL)
	}
	if gotStart != "10" { // (page2-1)*size10
		t.Errorf("startAt = %q, want 10", gotStart)
	}
	if gotMax != "10" {
		t.Errorf("maxResults = %q, want 10", gotMax)
	}
}

func TestList_KeyLikeQueryAddsKeyClause(t *testing.T) {
	var gotJQL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotJQL = r.URL.Query().Get("jql")
		_, _ = w.Write([]byte(`{"total":0,"issues":[]}`))
	}))
	defer srv.Close()
	c := newTestClient(srv.URL)
	if _, _, err := c.List(context.Background(), tasks.ListParams{Query: "sts-9", Page: 1, Size: 20}); err != nil {
		t.Fatalf("List err: %v", err)
	}
	if !strings.Contains(gotJQL, `key = "STS-9"`) {
		t.Errorf("key-like query should add uppercased key clause; got %q", gotJQL)
	}
}

func TestGet_ADFDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rest/api/2/issue/STS-5" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"key":"STS-5","fields":{
			"summary":"A","status":{"name":"Open","statusCategory":{"key":"new"}},
			"reporter":{"displayName":"Bob"},"labels":["sec","web"],
			"description":{"type":"doc","content":[
				{"type":"paragraph","content":[{"type":"text","text":"Hello "},{"type":"text","text":"world"}]},
				{"type":"paragraph","content":[{"type":"text","text":"second"}]}
			]}}}`))
	}))
	defer srv.Close()
	c := newTestClient(srv.URL)
	d, err := c.Get(context.Background(), "STS-5")
	if err != nil {
		t.Fatalf("Get err: %v", err)
	}
	if d.Reporter != "Bob" || d.StatusCategory != tasks.CategoryTodo {
		t.Errorf("detail base wrong: %+v", d)
	}
	if len(d.Labels) != 2 || d.Labels[0] != "sec" {
		t.Errorf("labels wrong: %v", d.Labels)
	}
	if !strings.Contains(d.Description, "Hello world") || !strings.Contains(d.Description, "second") {
		t.Errorf("ADF text wrong: %q", d.Description)
	}
	if !strings.HasSuffix(d.URL, "/browse/STS-5") {
		t.Errorf("URL wrong: %q", d.URL)
	}
}

func TestGet_PlainStringDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		desc, _ := json.Marshal("just a string desc")
		_, _ = w.Write([]byte(`{"key":"STS-1","fields":{"summary":"x","description":` + string(desc) + `}}`))
	}))
	defer srv.Close()
	c := newTestClient(srv.URL)
	d, err := c.Get(context.Background(), "STS-1")
	if err != nil {
		t.Fatalf("Get err: %v", err)
	}
	if d.Description != "just a string desc" {
		t.Errorf("plain desc wrong: %q", d.Description)
	}
	if d.Labels == nil {
		t.Errorf("labels should be non-nil empty slice")
	}
}

func TestGet_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessages":["Issue does not exist"]}`))
	}))
	defer srv.Close()
	c := newTestClient(srv.URL)
	_, err := c.Get(context.Background(), "STS-999")
	var e *apperr.Error
	if !errors.As(err, &e) || e.Kind != apperr.KindNotFound {
		t.Fatalf("expected not-found apperr, got %v", err)
	}
}

func TestNotConfigured(t *testing.T) {
	// Нет base URL и токена.
	c := New(Config{ProjectKey: "STS"})
	if _, _, err := c.List(context.Background(), tasks.ListParams{Page: 1, Size: 10}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("List: expected ErrNotConfigured, got %v", err)
	}
	if _, err := c.Get(context.Background(), "STS-1"); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("Get: expected ErrNotConfigured, got %v", err)
	}
	// Base URL есть, токена нет — тоже не настроено.
	c2 := New(Config{BaseURL: "https://jira.example", ProjectKey: "STS"})
	if _, _, err := c2.List(context.Background(), tasks.ListParams{Page: 1, Size: 10}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("List(no token): expected ErrNotConfigured, got %v", err)
	}
}

func TestBasicAuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
			t.Errorf("expected Basic auth for Cloud, got %q", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"total":0,"issues":[]}`))
	}))
	defer srv.Close()
	c := New(Config{BaseURL: srv.URL, Email: "me@x.com", Token: "tok", ProjectKey: "STS", APIVersion: "2"})
	if _, _, err := c.List(context.Background(), tasks.ListParams{Page: 1, Size: 5}); err != nil {
		t.Fatalf("List err: %v", err)
	}
}
