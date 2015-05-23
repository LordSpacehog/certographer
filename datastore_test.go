package ca

import (
	"crypto/x509"
	"math/big"
	"testing"
)

func TestNewMemdatastore(t *testing.T) {
	mds := NewMemDatastore()
	if mds == nil {
		t.Errorf("returned nil datastore")
	}

	var ds Datastore
	ds = mds
	if ds == nil {
		t.Errorf("NewMemDatastore returned non-datastore")
	}
	return
}

func TestMemDatastoreStoreCAKey(t *testing.T) {
	mds := NewMemDatastore()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}

	err := mds.StoreCACert(cert)
	if err != nil {
		t.Errorf("could not store CA certificate")
	}
}

func TestMemDatastoreGetCACert(t *testing.T) {
	mds := NewMemDatastore()

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}

	err := mds.StoreCACert(cert)
	if err != nil {
		t.Errorf("could not store CA certificate")
	}

	cac, err := mds.GetCACert()
	if err != nil {
		t.Errorf("could not retrieve CA cert")
	}

	if !cac.Equal(cert) {
		t.Errorf("retrieved certificate does not match stored certificate")
	}
}

func TestStore(t *testing.T) {
	mds := NewMemDatastore()

	numCerts := 1000
	certList := make([]*x509.Certificate, numCerts)
	for i := range certList {
		certList[i] = &x509.Certificate{
			SerialNumber: big.NewInt(int64(i)),
		}
		err := mds.Store(certList[i])
		if err != nil {
			t.Errorf("failed to store cert %d", i)
		}
	}
}
