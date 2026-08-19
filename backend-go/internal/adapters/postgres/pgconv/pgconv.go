// Package pgconv — конвертеры между доменными Go-типами и pgtype (pgx v5),
// общие для всех репозиториев (nullable-поля, указатели, время).
package pgconv

import (
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

// Text: string → pgtype.Text (пустая строка → NULL).
func Text(s string) pgtype.Text { return pgtype.Text{String: s, Valid: s != ""} }

// TextPtr: *string → pgtype.Text (nil → NULL, иначе значение даже пустое).
func TextPtr(s *string) pgtype.Text {
	if s == nil {
		return pgtype.Text{}
	}
	return pgtype.Text{String: *s, Valid: true}
}

// TextVal: pgtype.Text → string ("" если NULL).
func TextVal(t pgtype.Text) string {
	if t.Valid {
		return t.String
	}
	return ""
}

// TextValPtr: pgtype.Text → *string (nil если NULL).
func TextValPtr(t pgtype.Text) *string {
	if !t.Valid {
		return nil
	}
	s := t.String
	return &s
}

// Int4: *int32 → pgtype.Int4 (nil → NULL).
func Int4(p *int32) pgtype.Int4 {
	if p == nil {
		return pgtype.Int4{}
	}
	return pgtype.Int4{Int32: *p, Valid: true}
}

// Int4Val: pgtype.Int4 → *int32 (nil если NULL).
func Int4Val(v pgtype.Int4) *int32 {
	if !v.Valid {
		return nil
	}
	x := v.Int32
	return &x
}

// Ts: time.Time → pgtype.Timestamptz (Valid=true).
func Ts(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }

// TsPtr: *time.Time → pgtype.Timestamptz (nil → NULL).
func TsPtr(t *time.Time) pgtype.Timestamptz {
	if t == nil {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: *t, Valid: true}
}

// TsVal: pgtype.Timestamptz → time.Time (нулевое время если NULL).
func TsVal(t pgtype.Timestamptz) time.Time {
	if t.Valid {
		return t.Time
	}
	return time.Time{}
}

// TsValPtr: pgtype.Timestamptz → *time.Time (nil если NULL).
func TsValPtr(t pgtype.Timestamptz) *time.Time {
	if !t.Valid {
		return nil
	}
	x := t.Time
	return &x
}
