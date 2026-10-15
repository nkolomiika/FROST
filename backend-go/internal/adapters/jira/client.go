// Package jira — адаптер к Jira REST API, реализующий порт tasks.Client.
// Только чтение: листинг задач проекта (JQL) и карточка задачи по ключу.
// Используется обычный net/http (НЕ netguard): Jira — доверенный эндпоинт,
// заданный админом через env, и может жить во внутренней сети.
package jira

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nkolomiika/frost/internal/app/tasks"
	"github.com/nkolomiika/frost/internal/apperr"
)

// ErrNotConfigured — Jira не настроена (нет base URL или токена). Роут при этом
// существует и отвечает понятным сообщением вместо 404.
var ErrNotConfigured = apperr.New(apperr.KindInternal, "Интеграция с Jira не настроена")

const maxBodyBytes = 4 << 20 // 4 MiB на ответ Jira

// Config — параметры подключения к Jira.
type Config struct {
	BaseURL    string
	Email      string // задан ⇒ Basic (Jira Cloud); пусто ⇒ Bearer PAT (Server/DC)
	Token      string
	APIVersion string // "2" (Server/DC, старый Cloud) или "3" (Cloud)
	ProjectKey string
	Timeout    time.Duration
	MaxResults int
}

// Client — HTTP-клиент Jira.
type Client struct {
	baseURL    string
	email      string
	token      string
	apiVersion string
	projectKey string
	maxResults int
	http       *http.Client
}

// New собирает клиент Jira с таймаутом и дефолтами.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	ver := strings.TrimSpace(cfg.APIVersion)
	if ver == "" {
		ver = "2"
	}
	pk := strings.TrimSpace(cfg.ProjectKey)
	if pk == "" {
		pk = "STS"
	}
	return &Client{
		baseURL:    strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
		email:      strings.TrimSpace(cfg.Email),
		token:      cfg.Token,
		apiVersion: ver,
		projectKey: pk,
		maxResults: cfg.MaxResults,
		http:       &http.Client{Timeout: timeout},
	}
}

func (c *Client) configured() bool { return c.baseURL != "" && c.token != "" }

func (c *Client) apiPath(suffix string) string { return "/rest/api/" + c.apiVersion + suffix }

func (c *Client) setAuth(req *http.Request) {
	switch {
	case c.email != "":
		cred := base64.StdEncoding.EncodeToString([]byte(c.email + ":" + c.token))
		req.Header.Set("Authorization", "Basic "+cred)
	case c.token != "":
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}

// do выполняет GET и возвращает (тело ≤maxBodyBytes, статус, ошибка транспорта).
func (c *Client) do(ctx context.Context, path string, q url.Values) ([]byte, int, error) {
	u := c.baseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, apperr.New(apperr.KindInternal, "Jira: некорректный запрос")
	}
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, apperr.New(apperr.KindInternal, "Jira недоступна")
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return body, resp.StatusCode, nil
}

// List возвращает страницу задач проекта по JQL и общее число найденного.
func (c *Client) List(ctx context.Context, params tasks.ListParams) ([]tasks.Task, int64, error) {
	if !c.configured() {
		return nil, 0, ErrNotConfigured
	}
	size := params.Size
	if c.maxResults > 0 && size > c.maxResults {
		size = c.maxResults
	}
	startAt := (params.Page - 1) * size
	if startAt < 0 {
		startAt = 0
	}
	q := url.Values{}
	q.Set("jql", c.buildJQL(params))
	q.Set("startAt", strconv.Itoa(startAt))
	q.Set("maxResults", strconv.Itoa(size))
	q.Set("fields", "summary,status,issuetype,priority,assignee,updated,created")

	body, code, err := c.do(ctx, c.apiPath("/search"), q)
	if err != nil {
		return nil, 0, err
	}
	if code < 200 || code >= 300 {
		return nil, 0, apperr.New(apperr.KindInternal, fmt.Sprintf("Jira вернула ошибку: %d", code))
	}
	var sr searchResp
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, 0, apperr.New(apperr.KindInternal, "Jira: не удалось разобрать ответ")
	}
	items := make([]tasks.Task, 0, len(sr.Issues))
	for i := range sr.Issues {
		items = append(items, mapIssue(&sr.Issues[i]))
	}
	return items, sr.Total, nil
}

// Get возвращает полную карточку задачи по ключу.
func (c *Client) Get(ctx context.Context, key string) (*tasks.TaskDetail, error) {
	if !c.configured() {
		return nil, ErrNotConfigured
	}
	q := url.Values{}
	q.Set("fields", "summary,status,issuetype,priority,assignee,reporter,updated,created,description,labels")

	body, code, err := c.do(ctx, c.apiPath("/issue/"+url.PathEscape(key)), q)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, apperr.NotFound("Задача не найдена")
	}
	if code < 200 || code >= 300 {
		return nil, apperr.New(apperr.KindInternal, fmt.Sprintf("Jira вернула ошибку: %d", code))
	}
	var iss issue
	if err := json.Unmarshal(body, &iss); err != nil {
		return nil, apperr.New(apperr.KindInternal, "Jira: не удалось разобрать ответ")
	}
	d := &tasks.TaskDetail{Task: mapIssue(&iss)}
	d.Reporter = userName(iss.Fields.Reporter)
	d.Description = adfToText(iss.Fields.Description)
	d.Labels = iss.Fields.Labels
	if d.Labels == nil {
		d.Labels = []string{}
	}
	d.URL = c.baseURL + "/browse/" + key
	return d, nil
}

// keyLike — значение поиска, похожее на ключ задачи (PROJ-123). Только для таких
// добавляем в JQL ветку `key = "..."` — иначе Jira отвергнет невалидный ключ.
var keyLike = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]+-\d+$`)

// buildJQL строит JQL: проект + (поиск по summary/ключу) + (фильтр категории) + сортировка.
func (c *Client) buildJQL(p tasks.ListParams) string {
	var sb strings.Builder
	sb.WriteString(`project = "`)
	sb.WriteString(jqlEscape(c.projectKey))
	sb.WriteString(`"`)
	if p.Query != "" {
		q := jqlEscape(p.Query)
		if keyLike.MatchString(p.Query) {
			sb.WriteString(` AND (summary ~ "` + q + `*" OR key = "` + strings.ToUpper(q) + `")`)
		} else {
			sb.WriteString(` AND summary ~ "` + q + `*"`)
		}
	}
	switch p.Category {
	case tasks.CategoryTodo:
		sb.WriteString(` AND statusCategory = "To Do"`)
	case tasks.CategoryInProgress:
		sb.WriteString(` AND statusCategory = "In Progress"`)
	case tasks.CategoryDone:
		sb.WriteString(` AND statusCategory = "Done"`)
	}
	sb.WriteString(" ORDER BY updated DESC")
	return sb.String()
}

func jqlEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// ---- Jira JSON ----

type searchResp struct {
	Total  int64   `json:"total"`
	Issues []issue `json:"issues"`
}

type issue struct {
	Key    string `json:"key"`
	Fields fields `json:"fields"`
}

type fields struct {
	Summary     string          `json:"summary"`
	Status      *status         `json:"status"`
	IssueType   *named          `json:"issuetype"`
	Priority    *named          `json:"priority"`
	Assignee    *user           `json:"assignee"`
	Reporter    *user           `json:"reporter"`
	Updated     string          `json:"updated"`
	Created     string          `json:"created"`
	Labels      []string        `json:"labels"`
	Description json.RawMessage `json:"description"`
}

type status struct {
	Name           string  `json:"name"`
	StatusCategory *named2 `json:"statusCategory"`
}

type named struct {
	Name string `json:"name"`
}

type named2 struct {
	Key string `json:"key"`
}

type user struct {
	DisplayName  string `json:"displayName"`
	Name         string `json:"name"`
	EmailAddress string `json:"emailAddress"`
}

func mapIssue(iss *issue) tasks.Task {
	f := iss.Fields
	t := tasks.Task{
		Key:            iss.Key,
		Summary:        f.Summary,
		Updated:        f.Updated,
		Created:        f.Created,
		StatusCategory: tasks.CategoryUnknown,
	}
	if f.Status != nil {
		t.Status = f.Status.Name
		t.StatusCategory = mapStatusCategory(f.Status)
	}
	if f.IssueType != nil {
		t.IssueType = f.IssueType.Name
	}
	if f.Priority != nil {
		t.Priority = f.Priority.Name
	}
	t.Assignee = userName(f.Assignee)
	return t
}

// mapStatusCategory приводит Jira statusCategory.key к нашей категории.
func mapStatusCategory(s *status) string {
	if s == nil || s.StatusCategory == nil {
		return tasks.CategoryUnknown
	}
	switch strings.ToLower(s.StatusCategory.Key) {
	case "new":
		return tasks.CategoryTodo
	case "indeterminate":
		return tasks.CategoryInProgress
	case "done":
		return tasks.CategoryDone
	default:
		return tasks.CategoryUnknown
	}
}

func userName(u *user) string {
	if u == nil {
		return ""
	}
	if u.DisplayName != "" {
		return u.DisplayName
	}
	if u.Name != "" {
		return u.Name
	}
	return u.EmailAddress
}

// ---- ADF / plain description ----

type adfNode struct {
	Type    string    `json:"type"`
	Text    string    `json:"text"`
	Content []adfNode `json:"content"`
}

// adfToText превращает описание задачи в текст: Jira Server отдаёт строку,
// Jira Cloud — ADF-документ ({"type":"doc","content":[...]}). Никогда не паникует.
func adfToText(raw json.RawMessage) string {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 || string(b) == "null" {
		return ""
	}
	// Простая строка (Server/DC, wiki-markup).
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		return s
	}
	// ADF-документ (Cloud).
	var doc adfNode
	if err := json.Unmarshal(b, &doc); err != nil {
		return ""
	}
	var sb strings.Builder
	walkADF(&doc, &sb)
	return strings.TrimSpace(sb.String())
}

func walkADF(n *adfNode, sb *strings.Builder) {
	if n == nil {
		return
	}
	if n.Text != "" {
		sb.WriteString(n.Text)
	}
	for i := range n.Content {
		walkADF(&n.Content[i], sb)
	}
	switch n.Type {
	case "paragraph", "heading", "listItem", "blockquote", "codeBlock":
		sb.WriteString("\n")
	}
}
