package certmanager

import (
	"context"
	"encoding/json"
	"log"
	"time"
)

func (m *Manager) renew(ctx context.Context) {
	rows, err := m.db.QueryxContext(ctx, "SELECT domain, email, resource FROM certificates")
	if err != nil {
		log.Printf("failed checking renew for certificates: %v", err)
		return
	}
	model := &CertificateModel{}
	renew := []CertificateResource{}
	defer rows.Close()
	for rows.Next() {
		if err := rows.StructScan(model); err != nil {
			log.Printf("Failed scanning certificate row: %v", err)
			return
		}
		res := CertificateResource{}
		if err := json.Unmarshal([]byte(model.Resource), &res); err != nil {
			log.Printf("Failed unmarshal cert resource: %s: %v", model.Domain, err)
			return
		}
		x, err := certResultFromResource(model.Domain, res)
		if err != nil {
			log.Printf("Failed creating certificate result: %s: %v", model.Domain, err)
			return
		}
		log.Printf("  %v %v", x.Certificate.NotAfter, time.Now().Add(m.cfg.RenewWhenRemaining))
		if time.Now().Add(m.cfg.RenewWhenRemaining).After(x.Certificate.NotAfter) {
			renew = append(renew, res)
		}
	}
	rows.Close()
	for _, res := range renew {
		if err := m.renewCertificate(res); err != nil {
			log.Printf("renew failed: %s: %v", res.Domain, err)
		}
	}
}

func (m *Manager) RenewLoop(ctx context.Context) {
	go func() {
		for {
			m.renew(ctx)
			timer := time.NewTimer(10 * time.Minute)
			select {
			case <-timer.C:
				continue
			case <-ctx.Done():
				return
			}
		}
	}()
}
