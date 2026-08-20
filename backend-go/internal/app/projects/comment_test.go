package projects

import (
	"context"
	"testing"
)

// Порт test_comment_service.py, адаптированный к NoteComment проектов
// (в контексте projects комментарии — к заметкам; уязвимостные CommentService
// живут в другом контексте вне пакета projects). Проверяем перенесённые
// поведения: править/удалять можно только свой комментарий (даже админ — нет),
// а редактирование не рассылает уведомлений по @упоминаниям.

// Даже админ не может редактировать чужой комментарий.
func TestUpdateNoteCommentForbiddenForNonAuthor(t *testing.T) {
	f := newFakeStore()
	f.noteComment = &NoteComment{ID: 10, ProjectID: 1, NoteID: 2, UserID: 500, Content: "old"}
	svc := NewService(f, noopCipher{}, fixedNow)

	admin := Actor{ID: 999, Role: "ADMIN"}
	_, err := svc.UpdateNoteComment(context.Background(), 1, 2, 10, "hacked", admin)
	if !isForbidden(err, "только свой комментарий") {
		t.Fatalf("want Forbidden 'только свой комментарий', got %v", err)
	}
}

// Даже админ не может удалить чужой комментарий.
func TestDeleteNoteCommentForbiddenForNonAuthor(t *testing.T) {
	f := newFakeStore()
	f.noteComment = &NoteComment{ID: 11, ProjectID: 1, NoteID: 2, UserID: 500}
	svc := NewService(f, noopCipher{}, fixedNow)

	admin := Actor{ID: 999, Role: "ADMIN"}
	err := svc.DeleteNoteComment(context.Background(), 1, 2, 11, admin)
	if !isForbidden(err, "только свой комментарий") {
		t.Fatalf("want Forbidden 'только свой комментарий', got %v", err)
	}
}

// Редактирование комментария не создаёт уведомлений по упоминаниям.
func TestUpdateNoteCommentMentionsDoNotCreateNotifications(t *testing.T) {
	f := newFakeStore()
	f.noteComment = &NoteComment{ID: 12, ProjectID: 1, NoteID: 2, UserID: 7, Content: "old"}
	f.usersByName["target"] = UserBrief{ID: 8, Username: "target"}
	svc := NewService(f, noopCipher{}, fixedNow)

	author := Actor{ID: 7, Username: "author", Role: "PENTESTER"}
	if _, err := svc.UpdateNoteComment(context.Background(), 1, 2, 12, "updated @target", author); err != nil {
		t.Fatalf("UpdateNoteComment: %v", err)
	}
	if len(f.notifications) != 0 {
		t.Fatalf("notifications = %d, want 0 (редактирование не уведомляет по @упоминаниям)", len(f.notifications))
	}
}
