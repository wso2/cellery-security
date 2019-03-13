package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

func loadX509Certificate(certFile string) (*x509.Certificate, error) {
	payload, err := readPemPayload(certFile)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(payload.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func loadPrivateKey(keyFile string) (*rsa.PrivateKey, error) {
	payload, err := readPemPayload(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS1PrivateKey(payload.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func readPemPayload(file string) (*pem.Block, error) {
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	payload, _ := pem.Decode(bytes)
	return payload, nil
}
