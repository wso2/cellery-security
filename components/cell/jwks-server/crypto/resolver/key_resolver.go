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
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	b64 "encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/cellery-io/mesh-security/components/cell/jwks-server/resources"
	"log"
	"math/big"
	"time"
)

var (
	keyB  []byte
	certB []byte
)

func KeyGenerator() (resources.JwksJson, error) {
	keyBytes, certBytes, err := getKeyPair()
	if err != nil {
		return resources.JwksJson{}, err
	}
	jwksJson, err := KeyResolver(keyBytes, certBytes)
	if err != nil {
		return jwksJson, err
	}
	return jwksJson, nil
}

func KeyResolver(privateKeyBytes []byte, certificateBytes []byte) (resources.JwksJson, error) {
	blockPriv, _ := pem.Decode([]byte(privateKeyBytes))
	// To get RSA Private key
	key, err := x509.ParsePKCS1PrivateKey(blockPriv.Bytes)
	if err != nil {
		log.Printf("Error parsing the private key. %s\n", err)
		return resources.JwksJson{}, err
	}

	blockCert, _ := pem.Decode([]byte(certificateBytes))
	// To obtain a single certificate from the given ASN.1 DER data.
	cert, err := x509.ParseCertificate(blockCert.Bytes)
	if err != nil {
		log.Printf("Error parsing the certificate. %s\n", err)
		return resources.JwksJson{}, err
	}
	log.Println("Decoded and parsed the key and the cert.")
	if cert == nil {
		log.Println("Error locating the cert. Cert reference is nil.")
		return resources.JwksJson{}, nil
	}
	certification := encodeCert(cert.Raw)
	jwksJson := generateJson(certification, key.PublicKey)
	return jwksJson, nil
}

func getKeyPair() ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("Failed to generate private key. %s\n", err)
		return nil, nil, err
	}
	log.Println("Generated keys successfully.")

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour*time.Duration(10) +
		time.Minute*time.Duration(10) +
		time.Second*time.Duration(0))

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Printf("Failed to generate the serial number. %s\n", err)
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Cellery Sample STS Cert"},
			CommonName:   "Cellery",
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
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)

	if err != nil {
		log.Printf("Error creating the cert. %s", err)
		return nil, nil, err
	}
	certBlock := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	log.Println("Generated cert successfully.")

	keyB = pem.EncodeToMemory(&privateKeyBlock)
	certB = pem.EncodeToMemory(&certBlock)
	return pem.EncodeToMemory(&privateKeyBlock), pem.EncodeToMemory(&certBlock), nil
}

func GetKeyAndCertBytes() ([]byte, []byte) {
	return keyB, certB
}

func encodeCert(certBytes []byte) string {
	h := sha1.New()
	h.Write(certBytes)
	hashSum := h.Sum(nil)
	log.Println("Hash SHA1 sum for the cert generated successfully.")
	sEnc := b64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%x", hashSum)))
	log.Println("Encoded the cert to base 64.")
	return sEnc
}

func generateJson(certification string, publicKey rsa.PublicKey) resources.JwksJson {
	var newKey = resources.Key{
		Alg: "RS256",
		Use: "sig",
		Kid: certification,
		Kty: "RSA",
		E:   b64.RawStdEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		N:   b64.RawStdEncoding.EncodeToString(publicKey.N.Bytes()),
	}
	jwks := resources.JwksJson{
		Keys: []resources.Key{newKey},
	}
	return jwks
}
