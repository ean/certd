package api

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"ngrd.no/certd/api/client"
	"ngrd.no/certd/certmanager"
	"ngrd.no/certd/config"
	"ngrd.no/certd/helpers"
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

func errorPage(w http.ResponseWriter, statusCode int, format string, args ...interface{}) {
	content := fmt.Sprintf(format, args...)
	w.WriteHeader(statusCode)
	if _, err := w.Write([]byte(content)); err != nil {
		log.Printf("failed writing error page")
		return
	}
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errorPage(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	domain := r.URL.Query().Get("domain")
	res, err := s.mgr.GetCertificate(domain)
	if err != nil {
		errorPage(w, http.StatusInternalServerError, "unable to get certificate: %v", err)
		return
	}
	apires := &client.GetCertificateResponse{
		Certificate: res.Certificate,
		Issuer:      res.IssuerCertificate,
		PrivateKey:  res.PrivateKey,
	}
	if err := json.NewEncoder(w).Encode(apires); err != nil {
		errorPage(w, http.StatusInternalServerError, "failed serializing response: %v", err)
		return
	}
}

func filterRequests(nets []net.IPNet) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				errorPage(w, http.StatusInternalServerError, "bad remote addr format: %v", err)
				return
			}
			ip := net.ParseIP(addr)
			if ip == nil {
				errorPage(w, http.StatusInternalServerError, "unable to parse remote ip address: %v", addr)
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
				errorPage(w, http.StatusForbidden, "you are not allowed")
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
