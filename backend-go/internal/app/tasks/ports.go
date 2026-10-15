package tasks

import "context"

// Client — порт к внешнему трекеру (Jira). Реализуется в adapters/jira.
// Сервис не знает ни про HTTP, ни про формат Jira.
type Client interface {
	// List возвращает страницу задач проекта с учётом поиска/фильтра и общее число.
	List(ctx context.Context, params ListParams) (items []Task, total int64, err error)
	// Get возвращает полную карточку задачи по ключу (напр. "STS-123").
	Get(ctx context.Context, key string) (*TaskDetail, error)
}
