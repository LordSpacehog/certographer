/*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, see <http://www.gnu.org/licenses/>.
*
* Copyright (C) Alex Swehla,
 */

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

type CA struct {
	privateKey  interface{}
	certificate *x509.Certificate
	datastore   Datastore
}

type AuthorityKeyIdentifier struct {
	KeyIdentifier             []byte
	AuthorityCertIssuer       []byte
	AuthorityCertSerialNumber []byte
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

/*
func GenerateCA(keyType string, bitDepth int, expiration int, subject pkix.Name) (interface{}, *x509.Certificate, error) {

	switch keyType {
	case "ecdsa":
		privateKey, err := ecdsa.GenerateKey(rand.Reader, bitDepth)
		break
	case "rsa":
		privateKey, err := rsa.GenerateKey(rand.Reader, bitDepth)
		break
	default:
		return nil, nil, errors.New("Key type not supported!")
	}

	template := newCertificate()
	template.Subject = subject

	return privateKey, certificate, nil
}
*/
