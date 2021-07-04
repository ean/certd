package helpers

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"src.ngrd.no/certd/api/client"
)

func getKeyPair(domain string) (*tls.Certificate, error) {
	cert, err := client.Get(domain, "srv01.a.ps13.no")
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair([]byte(cert.Certificate), []byte(cert.PrivateKey))
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

func TLSListenAndServe(domain string, address string, mux http.Handler) error {
	return TLSListenAndServeFn(domain, address, mux, getKeyPair)
}

func TLSListenAndServeFn(domain string, address string, mux http.Handler, fn func(domain string) (*tls.Certificate, error)) error {
	server := &http.Server{Addr: address, Handler: mux}
	l := sync.Mutex{}
	keyPair, err := fn(domain)
	if err != nil {
		return fmt.Errorf("get certificate: %w", err)
	}

	go func() {
		for {
			pair, err := fn(domain)
			if err != nil {
				log.Printf("Failed getting updated cert: %v", err)
			} else {
				l.Lock()
				keyPair = pair
				l.Unlock()
			}
			time.Sleep(10 * time.Hour)
		}
	}()

	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen: %s: %w", address, err)
	}

	defer ln.Close()
	config := &tls.Config{}
	config.NextProtos = []string{"http/1.1"}
	config.GetCertificate = func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
		l.Lock()
		defer l.Unlock()
		return keyPair, nil
	}
	tlsListener := tls.NewListener(ln, config)
	return server.Serve(tlsListener)
}
