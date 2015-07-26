package certographer

type CA struct {
	privateKey  interface{}
	certificate *x509.Certificate
	datastore   Datastore
}

func (ca *CA) IssueKeypair(template KeypairParams) (interface{}, *x509.Certificate, error) {
	switch template.KeyType {
	case "RSA":
		key, cert, err := issueRSAKeypair(template)
		return key, cert, err
	case "ECDSA":
		key, cert, err := issueECDSAKeypair(template)
		return key, cert, err
	default:
		return _, _, errors.New("Specified key type not supported")
	}
}

func (ca *CA) issueRSAKeypair(template KeypairParams) (interface{}, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, template.KeyLength)
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.PublicKey

	certificate, err := newCertificate()
	if err != nil {
		return nil, err
	}

}
