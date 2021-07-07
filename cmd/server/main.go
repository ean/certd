package main

import (
	"context"
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/jmoiron/sqlx"
	"github.com/kelseyhightower/envconfig"
	_ "modernc.org/sqlite"
	"src.ngrd.no/certd/api"
	"src.ngrd.no/certd/certmanager"
	"src.ngrd.no/certd/config"
)

func main() {
	cfg := config.Config{}
	if err := envconfig.Process("", &cfg); err != nil {
		log.Fatalf("failed loading config from environment: %+v", err)
	}
	db, err := sqlx.Open("sqlite", cfg.DBPath)
	if err != nil {
		log.Fatal("sqlx.Open: ", err)
	}
	certmanager.MustCreateTables(db)
	mgr, err := certmanager.NewManager(db, cfg)
	if err != nil {
		log.Fatal("new manager: ", err)
	}
	mgr.RenewLoop(context.Background())
	_, err = mgr.GetCertificate(cfg.Hostname)
	if err != nil {
		log.Fatalf("get cert for hostname failed: %s: %v", cfg.Hostname, err)
	}

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	srv := api.NewServer(cfg, mgr)
	log.Fatal("server start: ", srv.Start(cfg.Address, cfg.Hostname))
}
