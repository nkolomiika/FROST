// Package db встраивает goose-миграции и применяет их на старте (Go-API сам
// создаёт схему — в отличие от Python, где схему делал create_all на startup).
package db

import (
	"database/sql"
	"embed"
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib" // sql-драйвер pgx
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// RunMigrations применяет все goose-миграции up к базе по DSN (идемпотентно).
func RunMigrations(dsn string) error {
	sqldb, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer sqldb.Close()

	goose.SetBaseFS(migrations)
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("dialect: %w", err)
	}
	goose.SetLogger(goose.NopLogger())
	if err := goose.Up(sqldb, "migrations"); err != nil {
		return fmt.Errorf("goose up: %w", err)
	}
	return nil
}
