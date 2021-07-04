package client

type GetCertificateResponse struct {
	Certificate string `json:"certificate"`
	Issuer      string `json:"issuer_certificate"`
	PrivateKey  string `json:"private_key"`
}
