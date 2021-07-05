package certmanager

import (
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/jmoiron/sqlx"
	"src.ngrd.no/certd/config"
)

type Manager struct {
	db      *sqlx.DB
	clients map[string]*lego.Client
	cfg     config.Config
}

func NewManager(db *sqlx.DB, cfg config.Config) (*Manager, error) {
	user, err := GetOrCreateUser(cfg, db)
	if err != nil {
		return nil, err
	}
	clients := map[string]*lego.Client{}
	for _, pair := range cfg.DomainProviderPairs {
		suffix := pair.DomainSuffix
		providerName := pair.ProviderName
		provider, err := NewDNSChallengeProviderByName(providerName)
		if err != nil {
			return nil, fmt.Errorf("new dns challenge provider: %w", err)
		}
		c, err := GetClient(cfg, user, provider)
		if err != nil {
			return nil, fmt.Errorf("get client: %w", err)
		}
		clients[suffix] = c
	}
	return &Manager{
		db:      db,
		clients: clients,
		cfg:     cfg,
	}, nil
}

func (m *Manager) chooseClient(domain string) (*lego.Client, error) {
	i := strings.Index(domain, ".")
	if i < 0 {
		return nil, fmt.Errorf("invalid domain format, no '.': %s", domain)
	}
	suffix := domain[i+1:]
	c, ok := m.clients[suffix]
	if !ok {
		return nil, fmt.Errorf("no provider found for: %s", domain)
	}
	return c, nil
}

type CertificateResource struct {
	Domain            string `json:"domain"`
	CertURL           string `json:"certUrl"`
	CertStableURL     string `json:"certStableUrl"`
	PrivateKey        string `json:"privateKey"`
	Certificate       string `json:"certificate"`
	IssuerCertificate string `json:"issuerCertificate"`
	CSR               string `json:"csr"`
}

type CertificateResult struct {
	Domain            string
	Certificate       *x509.Certificate
	PrivateKey        *rsa.PrivateKey
	IssuerCertificate *x509.Certificate
}

func (m *Manager) obtainCertificate(domain string) (*CertificateResource, error) {
	c, err := m.chooseClient(domain)
	if err != nil {
		return nil, err
	}
	resource, err := c.Certificate.Obtain(certificate.ObtainRequest{
		Domains:    []string{domain},
		Bundle:     false,
		MustStaple: false,
	})
	if err != nil {
		return nil, err
	}

	r, err := m.storeCertificateResource(domain, resource)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

func (m *Manager) storeCertificateResource(domain string, resource *certificate.Resource) (CertificateResource, error) {
	r := CertificateResource{
		Domain:            resource.Domain,
		CertURL:           resource.CertURL,
		CertStableURL:     resource.CertStableURL,
		PrivateKey:        string(resource.PrivateKey),
		Certificate:       string(resource.Certificate),
		IssuerCertificate: string(resource.IssuerCertificate),
		CSR:               string(resource.CSR),
	}
	data, err := json.Marshal(&r)
	if err != nil {
		return CertificateResource{}, err
	}
	_, err = m.db.Exec("INSERT OR REPLACE INTO certificates (domain, email, resource) VALUES(?, ?, ?)", domain, m.cfg.CertEmail, string(data))
	if err != nil {
		return CertificateResource{}, err
	}
	return r, nil
}

func certResultFromResource(domain string, r CertificateResource) (*CertificateResult, error) {
	a, _ := pem.Decode([]byte(r.Certificate))
	c, err := x509.ParseCertificate(a.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509 parse crt: %w", err)
	}
	b, _ := pem.Decode([]byte(r.IssuerCertificate))
	issuer, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return nil, fmt.Errorf("x509 parse issuer crt: %w", err)
	}
	privKeyPem, _ := pem.Decode([]byte(r.PrivateKey))
	key, err := x509.ParsePKCS1PrivateKey(privKeyPem.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse rsa priv key: %w", err)
	}

	return &CertificateResult{
		Domain:            domain,
		Certificate:       c,
		PrivateKey:        key,
		IssuerCertificate: issuer,
	}, nil
}

func (m *Manager) getCertificate(domain string) (*CertificateResource, error) {
	model := &CertificateModel{}
	err := m.db.Get(model, "SELECT domain, email, resource FROM certificates WHERE domain = ? AND email = ?", domain, m.cfg.CertEmail)
	if err != nil {
		return nil, err
	}
	res := CertificateResource{}
	if err := json.Unmarshal([]byte(model.Resource), &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (m *Manager) GetCertificate(domain string) (*CertificateResource, error) {
	if !m.cfg.ApprovedDomainSuffix(domain) {
		return nil, fmt.Errorf("domain is not approved")
	}
	res, err := m.getCertificate(domain)
	if err == sql.ErrNoRows {
		res, err = m.obtainCertificate(domain)
	} else if err != nil {
		return nil, err
	}

	return res, err
}

func (m *Manager) renewCertificate(res CertificateResource) error {
	certRes := certificate.Resource{
		Domain:            res.Domain,
		CertURL:           res.CertURL,
		CertStableURL:     res.CertStableURL,
		PrivateKey:        []byte(res.PrivateKey),
		Certificate:       []byte(res.Certificate),
		IssuerCertificate: []byte(res.IssuerCertificate),
		CSR:               []byte(res.CSR),
	}
	c, err := m.chooseClient(res.Domain)
	if err != nil {
		return err
	}
	newRes, err := c.Certificate.Renew(certRes, false, false, "")
	if err != nil {
		return err
	}
	r, err := m.storeCertificateResource(res.Domain, newRes)
	if err != nil {
		return err
	}
	_ = r
	return nil
}
