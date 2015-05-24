package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
)

func TestInitRSA(t *testing.T) {
	ds := NewMemDatastore()

	CA, err := InitRSA(ds, 2048,
		pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Squidwrench"},
			OrganizationalUnit: []string{"HQ"},
			Locality:           []string{"Poughkeepsie"},
			Province:           []string{"NY"},
			CommonName:         "Master... MASTER...",
		})
	if err != nil {
		t.Errorf("error instantiating RSA-base CA")
	}

	root := x509.NewCertPool()
	root.AddCert(CA.certificate)

	if _, err := CA.certificate.Verify(x509.VerifyOptions{Roots: root}); err != nil {
		t.Errorf("not a valid certificate: %s, %s", pem.EncodeToMemory(&pem.Block{Type: "Certificate", Bytes: CA.certificate.Raw}), err.Error())
	}
}
