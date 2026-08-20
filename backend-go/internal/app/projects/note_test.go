package projects

import (
	"context"
	"testing"
)

// reorder требует полный набор sibling-страниц.
func TestReorderRequiresFullSiblingSet(t *testing.T) {
	f := newFakeStore()
	projectID := int32(4)
	parentID := int32(20)
	// Родитель должен существовать (ensureParent → GetNote).
	f.notes[parentID] = &Note{ID: parentID, ProjectID: projectID, Title: "parent"}
	// Два sibling у родителя.
	f.siblingNotes = []Note{
		{ID: 21, ProjectID: projectID, ParentID: &parentID, SortOrder: 1},
		{ID: 22, ProjectID: projectID, ParentID: &parentID, SortOrder: 2},
	}
	svc := NewService(f, noopCipher{}, fixedNow)

	// Передаём только один из двух — неполный набор.
	_, err := svc.ReorderNotes(context.Background(), projectID, &parentID,
		[]ReorderItem{{ID: 21, SortOrder: 1}}, 99)
	if !isValidation(err) {
		t.Fatalf("want validation 'полный набор sibling', got %v", err)
	}
}
