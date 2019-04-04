package keyResolvers

import (
	"encoding/pem"
	"fmt"
)

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"log"
	"math/big"
	"os"
	"time"
)

var (
	priv          *rsa.PrivateKey
	certification string
	certBytes     []byte
	validFrom       = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor         = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
)

func KeyGenerator() (JwksJson, []byte, []byte) {
	generateKeys()
	var err error
	var notBefore time.Time
	if len(*validFrom) == 0 {
		notBefore = time.Now()
	} else {
		notBefore, err = time.Parse("Jan 2 15:04:05 2026", *validFrom)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse creation date: %s\n", err)
			os.Exit(1)
		}
	}

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("failed to generate serial number: %s\n", err)
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
	}
	certBlock := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}

	log.Println("Generated cert.")
	certification = EncodeCert(fmt.Sprintf("", HashSHA1(certBytes)))

	return GenerateJson(certification, priv.PublicKey) , pem.EncodeToMemory(&privateKeyBlock), pem.EncodeToMemory(&certBlock)
}

func generateKeys() {
	var err error
	priv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s\n", err)
	}
	log.Println("Generated keys.")
}