package projectsrepo

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// dateValPtr: pgtype.Date → *time.Time (nil если NULL).
func dateValPtr(d pgtype.Date) *time.Time {
	if !d.Valid {
		return nil
	}
	t := d.Time
	return &t
}

// toDate: *time.Time → pgtype.Date (nil → NULL).
func toDate(t *time.Time) pgtype.Date {
	if t == nil {
		return pgtype.Date{}
	}
	return pgtype.Date{Time: *t, Valid: true}
}

func itoa(v int32) string { return strconv.Itoa(int(v)) }

// titleFromDetails извлекает details["title"] из audit-details (JSON) как *string.
func titleFromDetails(raw []byte) *string {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	if v, ok := m["title"].(string); ok && v != "" {
		return &v
	}
	return nil
}
