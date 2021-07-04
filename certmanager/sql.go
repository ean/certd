package certmanager

import (
	"log"

	"github.com/jmoiron/sqlx"
)

func MustCreateTables(db *sqlx.DB) {
	if err := CreateTables(db); err != nil {
		log.Fatalf("CreateTables failed: %v", err)
	}
}

func CreateTables(db *sqlx.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
		    email TEXT PRIMARY KEY,
		    registration TEXT,
		    key TEXT
		)
`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`
CREATE TABLE IF NOT EXISTS certificates (
    domain TEXT PRIMARY KEY ,
    email TEXT,
    resource TEXT
)
`)
	if err != nil {
		return err
	}
	return nil
}
