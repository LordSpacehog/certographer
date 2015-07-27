package ca

import (
	"crypto/x509"
	"errors"
)

type CA struct {
	privateKey  interface{}
	certificate *x509.Certificate
	datastore   Datastore
}

func (ca *CA) IssueKeypair(template KeypairParams) (interface{}, *x509.Certificate, error) {
	switch template.KeyType {
	case "RSA":
		key, cert, err := ca.issueRSAKeypair(template)
		return key, cert, err
	//case "ECDSA":
	//	key, cert, err := issueECDSAKeypair(template)
	//	return key, cert, err
	default:
		return nil, &x509.Certificate{}, errors.New("Specified key type not supported")
	}
}

func (ca *CA) issueRSAKeypair(template KeypairParams) (interface{}, *x509.Certificate, error) {
	key, cert, err := newKeypair(template)
	if err != nil {
		return nil, &x509.Certificate{}, err
	}

	return key, cert, err
}
