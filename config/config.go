package config

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type IPNet net.IPNet

func (ipn *IPNet) Decode(value string) error {
	_, net, err := net.ParseCIDR(value)
	if err != nil {
		return err
	}
	*ipn = IPNet(*net)
	return nil
}

type DomainProviderPair struct {
	DomainSuffix string
	ProviderName string
}

func (p *DomainProviderPair) Decode(value string) error {
	elements := strings.Split(value, ":")
	if len(elements) != 2 {
		return fmt.Errorf("%s: wrong number of elements: %d", value, len(elements))
	}
	p.DomainSuffix = elements[0]
	p.ProviderName = elements[1]
	return nil
}

type Config struct {
	DBPath              string               `default:"certd.db" envconfig:"DB_PATH"`
	Address             string               `default:"0.0.0.0:9443"`
	Hostname            string               `required:"true"`
	CertEmail           string               `envconfig:"CERT_EMAIL" required:"true"`
	AllowedIPNets       []IPNet              `envconfig:"ALLOWED_IPNETS" required:"true"`
	ACMEIssuer          string               `default:"https://acme-staging-v02.api.letsencrypt.org/directory" envconfig:"ACME_ISSUER"`
	DomainProviderPairs []DomainProviderPair `envconfig:"DOMAIN_SUFFIXES_PROVIDER" required:"true"`
	RenewWhenRemaining  time.Duration        `envconfig:"RENEW_WHEN_REMAINING" default:"720h"`
	PreferredChain      string               `envconfig:"PREFERRED_CHAIN" default:""`
}

func (cfg Config) ApprovedDomainSuffix(domain string) bool {
	for _, pair := range cfg.DomainProviderPairs {
		s := pair.DomainSuffix
		if strings.HasSuffix(domain, "."+s) {
			prefix := domain[0 : len(domain)-len(s)-1]
			if strings.Contains(prefix, ".") { // Only allow domains without nesten children
				continue
			}
			return true
		}
	}
	return false
}
