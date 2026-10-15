package tasks

import (
	"context"
	"regexp"
	"strings"

	"github.com/nkolomiika/frost/internal/apperr"
)

// Config — настройки use-case'а (ключ проекта для справки/валидации).
type Config struct {
	ProjectKey string
}

// Service — use-cases раздела Tasks. Зависит только от порта Client.
type Service struct {
	client Client
	cfg    Config
}

// NewService собирает сервис задач.
func NewService(client Client, cfg Config) *Service {
	return &Service{client: client, cfg: cfg}
}

// issueKeyRe — допустимый ключ задачи Jira: PROJ-123 (проект буквами/цифрами/подчёркиванием).
var issueKeyRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]+-\d+$`)

// normalizeCategory приводит ввод фильтра к нормализованной категории; пустое =
// «все». Неизвестное значение трактуем как «все» (мягко, без ошибки).
func normalizeCategory(c string) string {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case CategoryTodo:
		return CategoryTodo
	case CategoryInProgress:
		return CategoryInProgress
	case CategoryDone:
		return CategoryDone
	default:
		return ""
	}
}

// List отдаёт страницу задач. Поиск тримится, категория нормализуется; клиент
// (Jira) сам строит JQL и считает total.
func (s *Service) List(ctx context.Context, params ListParams) ([]Task, int64, error) {
	params.Query = strings.TrimSpace(params.Query)
	params.Category = normalizeCategory(params.Category)
	if params.Page < 1 {
		params.Page = 1
	}
	if params.Size < 1 {
		params.Size = 1
	}
	return s.client.List(ctx, params)
}

// Get отдаёт полную карточку задачи. Ключ валидируется, чтобы не слать в Jira
// заведомо мусорные значения из пути.
func (s *Service) Get(ctx context.Context, key string) (*TaskDetail, error) {
	key = strings.TrimSpace(key)
	if !issueKeyRe.MatchString(key) {
		return nil, apperr.Validation("Некорректный ключ задачи")
	}
	return s.client.Get(ctx, strings.ToUpper(key))
}
