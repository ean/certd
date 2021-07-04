package certmanager

type CertificateModel struct {
	Domain   string
	Email    string
	Resource string
}

type UserModel struct {
	Email        string
	Registration string
	Key          string
}
