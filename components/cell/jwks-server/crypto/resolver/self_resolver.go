/*
 * Copyright (c) 2019 WSO2 Inc. (http:www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http:www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package resolver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"time"
)

var (
	certification string
	certBytes     []byte
	validFor        = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	PrivateKey []byte
	Cert []byte
)

func KeyGenerator() error{
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s\n", err)
		return err
	}
	log.Println("Generated keys.")

	notBefore := time.Now()
	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Printf("failed to generate serial number: %s\n", err)
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cellery Sample STS Cert"},
			CommonName: "Cellery",
		},

		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(priv),
	}

	certBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil{
		log.Printf("Error creating the cert. %s", err)
		return err
	}
	certBlock := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}

	log.Println("Generated cert.")
	certification = EncodeCert(certBytes)
	generateJson(certification, priv.PublicKey)
	PrivateKey = pem.EncodeToMemory(&privateKeyBlock)
	Cert = pem.EncodeToMemory(&certBlock)
	return nil
}

