// Package certographer provides methods for generating a Certificate Authority and managing SSL certificates
package ca

import (
	//"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	// "encoding/pem"
	// "errors"
	"math/big"
	"time"
)

// Parameters for Generating new Key,Cert pairs
type KeypairParams struct {
	// Desired Key Type (RSA Or ECDSA)
	KeyType string
	// Desired private key bit depth
	KeyLength int
	// If ECDSA Set Curve
	KeyCurve string
	// Subject Name for cert
	Name pkix.Name
	// Number Of Days Valid
	Expiration int
	// Enabled Cert Features
	Usage struct {
		DigitalSignature  bool
		ContentCommitment bool
		KeyEncipherment   bool
		DataEncipherment  bool
		KeyAgreement      bool
		CertSign          bool
		CRLSign           bool
		EncipherOnly      bool
		DecipherOnly      bool
	}
	ExtUsage struct {
		Any                        bool
		ServerAuth                 bool
		ClientAuth                 bool
		CodeSigning                bool
		EmailProtection            bool
		IPSECEndSystem             bool
		IPSECTunnel                bool
		IPSECUser                  bool
		TimeStamping               bool
		OCSPSigning                bool
		MicrosoftServerGatedCrypto bool
		NetscapeServerGatedCrypto  bool
	}
}

type AuthorityKeyIdentifier struct {
	KeyIdentifier             []byte
	AuthorityCertIssuer       []byte
	AuthorityCertSerialNumber []byte
}

func newKeypair(params KeypairParams) (interface{}, x509.Certificate, error) {
	switch params.KeyType {
	case "RSA":
		key, cert, err := newRSAKeypair(params)
		return key, cert, err
	case "ECDSA":
		key, cert, err := newECDSAKeypair(params)
		return key, cert, err
	default:
		return nil, nil, errors.New("Specified key type not supported")
	}
}

func newRSAKeypair(params KeypairParams) (*rsa.PrivateKey, *x509.Certificate, error) {
	certificate := newCertificate()

}

func InitRSA(datastore Datastore, bitDepth int, subject pkix.Name) (*CA, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitDepth)
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.PublicKey

	template, err := newCertificate()
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := asn1.Marshal(publicKey)
	if err != nil {
		return nil, err
	}

	subjectKeyID := sha1.Sum(publicKeyBytes)
	authCrtIssuer, err := asn1.Marshal(subject)
	if err != nil {
		return nil, err
	}

	authCrtSN, err := asn1.Marshal(template.SerialNumber)
	if err != nil {
		return nil, err
	}

	authKeyID := AuthorityKeyIdentifier{
		KeyIdentifier:             subjectKeyID[:],
		AuthorityCertIssuer:       authCrtIssuer,
		AuthorityCertSerialNumber: authCrtSN,
	}

	authorityKeyIdentifier, err := asn1.Marshal(authKeyID)
	if err != nil {
		return nil, err
	}

	template.Subject = subject
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	template.SubjectKeyId = subjectKeyID[:]
	template.AuthorityKeyId = authorityKeyIdentifier
	template.NotBefore = time.Now().Add(-5 * time.Minute).UTC()
	template.NotAfter = time.Now().AddDate(10, 0, 0).UTC()

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	certificate, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	datastore.StoreCAKey(privateKey)
	if err != nil {
		return nil, err
	}

	datastore.StoreCACert(certificate)
	if err != nil {
		return nil, err
	}

	ca, err := New(datastore)
	if err != nil {
		return nil, err
	}

	return ca, nil
}

func New(datastore Datastore) (*CA, error) {
	pk, err := datastore.GetCAKey()
	if err != nil {
		return nil, err
	}

	cert, err := datastore.GetCACert()
	if err != nil {
		return nil, err
	}

	return &CA{
		privateKey:  pk,
		certificate: cert,
		datastore:   datastore,
	}, nil
}

func newCertificate() (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	certificate := x509.Certificate{
		SerialNumber: serialNumber,
	}
	return &certificate, nil
}
