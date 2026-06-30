package cli

import (
	"os"

	"github.com/mora1n/nwall/internal/conf"
	"github.com/mora1n/nwall/internal/store"
)

func dbPath() string {
	if p := os.Getenv("NWALL_DB"); p != "" {
		return p
	}
	return store.DefaultPath
}

func loadConfig() (conf.Config, error) {
	db, err := store.Open(dbPath())
	if err != nil {
		return conf.Config{}, err
	}
	defer db.Close()
	return db.LoadConfig()
}

func saveConfigValue(cfg conf.Config) error {
	db, err := store.Open(dbPath())
	if err != nil {
		return err
	}
	defer db.Close()
	return db.SaveConfig(cfg)
}

func openStore() (*store.DB, error) {
	return store.Open(dbPath())
}
