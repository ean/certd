package certmanager

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"log"

	"github.com/go-acme/lego/v4/registration"
	"github.com/jmoiron/sqlx"
	"src.ngrd.no/certd/config"
)

// You'll need a user or account type that implements acme.User
type MyUser struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}
func (u MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}
func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func generateKey() *ecdsa.PrivateKey {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return privateKey
}

func GetOrCreateUser(cfg config.Config, db *sqlx.DB) (*MyUser, error) {
	user, err := GetUser(cfg, db)
	if err == sql.ErrNoRows {
		return CreateUser(cfg, db)
	} else if err != nil {
		return nil, err
	} else {
		return user, nil
	}
}

func GetUser(cfg config.Config, db *sqlx.DB) (*MyUser, error) {
	m := UserModel{}
	if err := db.Get(&m, "SELECT email, registration, key FROM users WHERE email = ?", cfg.CertEmail); err != nil {
		return nil, err
	}
	u := &MyUser{}
	u.Email = cfg.CertEmail
	block, _ := pem.Decode([]byte(m.Key))
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}
	u.Key = privateKey
	u.Registration = &registration.Resource{}
	if err := json.Unmarshal([]byte(m.Registration), &u.Registration); err != nil {
		return nil, err
	}

	return u, nil
}

func CreateUser(cfg config.Config, db *sqlx.DB) (*MyUser, error) {
	myUser := MyUser{
		Email:        cfg.CertEmail,
		Registration: nil,
		Key:          generateKey(),
	}
	client, err := GetClientWithoutProvider(cfg, &myUser)
	if err != nil {
		return nil, err
	}
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	myUser.Registration = reg
	x509Encoded, err := x509.MarshalECPrivateKey(myUser.Key.(*ecdsa.PrivateKey))
	if err != nil {
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})
	data, err := json.Marshal(&myUser.Registration)
	if err != nil {
		return nil, err
	}
	m := UserModel{
		Email:        myUser.Email,
		Registration: string(data),
		Key:          string(pemEncoded),
	}
	if _, err := db.Exec(`INSERT INTO users (email, registration, key) VALUES(?, ?, ?)`, m.Email, m.Registration, m.Key); err != nil {
		return nil, err
	}
	return &myUser, nil
}
