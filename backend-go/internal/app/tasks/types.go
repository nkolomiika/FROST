// Package tasks — use-cases раздела Tasks: задачи из Jira (проект STS),
// проксируются только на чтение. Зависит от порта Client (его реализует
// adapters/jira); в домене нет ни HTTP, ни Jira-специфики.
package tasks

// Категории статуса (нормализованные, независимо от названий статусов в Jira).
const (
	CategoryTodo       = "todo"
	CategoryInProgress = "inprogress"
	CategoryDone       = "done"
	CategoryUnknown    = "unknown"
)

// Task — строка списка задач.
type Task struct {
	Key            string
	Summary        string
	Status         string
	StatusCategory string // todo | inprogress | done | unknown
	IssueType      string
	Priority       string
	Assignee       string
	Updated        string
	Created        string
}

// TaskDetail — полная карточка задачи (отдельный эндпоинт, как карточка вульны).
type TaskDetail struct {
	Task
	Reporter    string
	Description string
	Labels      []string
	URL         string
}

// ListParams — параметры листинга: поиск по названию и фильтр по категории статуса.
type ListParams struct {
	Query    string // поиск по summary / ключу
	Category string // todo | inprogress | done | "" (все)
	Page     int
	Size     int
}
