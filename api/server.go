package api

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	"src.ngrd.no/certd/api/client"
	"src.ngrd.no/certd/certmanager"
	"src.ngrd.no/certd/config"
	"src.ngrd.no/certd/helpers"
)

type Server struct {
	allowedRanges []net.IPNet
	mgr           *certmanager.Manager
	mux           http.Handler
}

func (s *Server) Start(address string, domain string) error {
	return helpers.TLSListenAndServeFn(domain, address, s.mux, func(domain string) (*tls.Certificate, error) {
		r, err := s.mgr.GetCertificate(domain)
		if err != nil {
			return nil, err
		}
		pair, err := tls.X509KeyPair([]byte(r.Certificate), []byte(r.PrivateKey))
		if err != nil {
			return nil, err
		}
		return &pair, err
	})
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("method not allowed"))
		return
	}
	domain := r.URL.Query().Get("domain")
	res, err := s.mgr.GetCertificate(domain)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("unable to get certificate"))
		return
	}
	apires := &client.GetCertificateResponse{
		Certificate: res.Certificate,
		Issuer:      res.IssuerCertificate,
		PrivateKey:  res.PrivateKey,
	}
	if err := json.NewEncoder(w).Encode(apires); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(fmt.Sprintf("failed serializing response: %v", err)))
	}
}

func filterRequests(nets []net.IPNet) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("bad remote addr format: %v", err)))
				return
			}
			ip := net.ParseIP(addr)
			if ip == nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("unable to parse remote ip address: %v", addr)))
				return
			}
			allowed := false
			for _, net := range nets {
				if net.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte("you are not allowed"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func NewServer(cfg config.Config, manager *certmanager.Manager) *Server {
	nets := []net.IPNet{}
	for _, n := range cfg.AllowedIPNets {
		nets = append(nets, net.IPNet(n))
	}
	mux := &http.ServeMux{}
	s := &Server{
		allowedRanges: nets,
		mgr:           manager,
		mux:           filterRequests(nets)(mux),
	}
	mux.HandleFunc("/get", s.getCertificate)
	return s
}
