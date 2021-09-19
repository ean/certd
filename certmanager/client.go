package certmanager

import (
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"
	"ngrd.no/certd/config"
	"ngrd.no/log"
)

func init() {
	log, err := log.New(log.WithComponentName("github.com/go-acme/lego"), log.WithWriter(os.Stdout))
	if err != nil {
		panic(err)
	}
	legolog.Logger = log
}

func GetClientWithoutProvider(cfg config.Config, user registration.User) (*lego.Client, error) {
	config := lego.NewConfig(user)

	// This CA URL is configured for a local dev instance of Boulder running in Docker in a VM.
	config.CADirURL = cfg.ACMEIssuer
	config.Certificate.KeyType = certcrypto.RSA2048

	// A client facilitates communication with the CA server.
	client, err := lego.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("lego.Newclient: %w", err)
	}
	return client, nil
}

func GetClient(cfg config.Config, user registration.User, provider challenge.Provider) (*lego.Client, error) {
	client, err := GetClientWithoutProvider(cfg, user)
	if err != nil {
		return nil, err
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return nil, fmt.Errorf("set dns01 provider: %w", err)
	}
	return client, nil
}
