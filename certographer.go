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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
)

type CA struct {
	privateKey  interface{}
	certificate *x509.Certificate
	datastore   Datastore
}

func InitRSA(datastore Datastore, bitDepth int, subject pkix.Name) (*CA, error) {
	privateKey := rsa.GenerateKey(rand.Reader, bitDepth)

	template := newCertificate
	template.Subject = subject
	template.BasicConstraintsValid = true
	template.IsCA = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	ca := New(datastore)

	return ca, nil
}

func New(datastore Datastore) *CA {

	return &CA{
		privateKey:  privateKey,
		certificate: certificate,
		datastore:   datastore,
	}
}

func newCertficate() (*x509.Certificate, error) {
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
