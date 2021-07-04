// +build minimal

package certmanager

import (
	"fmt"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
)

func NewDNSChallengeProviderByName(name string) (challenge.Provider, error) {
	switch name {
	case "digitalocean":
		return digitalocean.NewDNSProvider()
	case "rfc2136":
		return rfc2136.NewDNSProvider()
	default:
		return nil, fmt.Errorf("unrecognized DNS provider: %s", name)
	}
}
