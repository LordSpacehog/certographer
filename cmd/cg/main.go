// Package main provides a command-line utility to expose certographer functionality
package main

import (
	//"flag"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/lordspacehog/certographer"
)

func main() {
	ds := ca.NewMemDatastore()

	_, err := ca.InitRSA(ds, 2048,
		pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Squidwrench"},
			OrganizationalUnit: []string{"HQ"},
			Locality:           []string{"Poughkeepsie"},
			Province:           []string{"NY"},
			CommonName:         "Master",
		})
	if err != nil {
		return
	}

	cert, err := ds.GetCACert()
	if err != nil {
		return
	}

	fmt.Printf("%s\n",
		pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}))
}
