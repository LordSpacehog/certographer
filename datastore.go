package ca

import (
	"crypto/x509"
	"math/big"
)

type Datastore interface {
	Store(cert *x509.Certificate) error
	StoreCAKey(privateKey interface{}) error
	StoreCACert(cert *x509.Certificate) error
	GetCAKey() (interface{}, error)
	GetCACert() (*x509.Certificate, error)
	FindByFingerprint(fp string) (*x509.Certificate, error)
	FindBySerialNumber(sn *big.Int) (*x509.Certificate, error)
	GetAllCerts() ([]*x509.Certificate, error)
}

type MemDatastore struct {
	caPrivateKey  interface{}
	caCertificate *x509.Certificate
	certs         []*x509.Certificate
}

func NewMemDatastore() *MemDatastore {
	return &MemDatastore{
		certs: []*x509.Certificate{},
	}
}

func (memds *MemDatastore) GetCAKey() (interface{}, error) {
	return memds.caPrivateKey, nil
}

func (memds *MemDatastore) GetCACert() (*x509.Certificate, error) {
	return memds.caCertificate, nil
}

func (memds *MemDatastore) Store(cert *x509.Certificate) error {
	memds.certs = append(memds.certs, cert)
	return nil
}

func (memds *MemDatastore) StoreCAKey(privateKey interface{}) error {
	memds.caPrivateKey = privateKey
	return nil
}

func (memds *MemDatastore) StoreCACert(cert *x509.Certificate) error {
	memds.caCertificate = cert
	return nil
}

func (memds *MemDatastore) FindByFingerprint(fp string) (*x509.Certificate, error) {
	return nil, nil
}

func (memds *MemDatastore) FindBySerialNumber(sn *big.Int) (*x509.Certificate, error) {
	return nil, nil
}

func (memds *MemDatastore) GetAllCerts() ([]*x509.Certificate, error) {
	return memds.certs, nil
}
