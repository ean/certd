// +build !minimal

package certmanager

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
)

func NewDNSChallengeProviderByName(name string) (challenge.Provider, error) {
	return dns.NewDNSChallengeProviderByName(name)
}
