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
	derBytes 	  []byte
	validFrom  = flag.String("start-date", "", "Creation date formatted as Jan 1 15:04:05 2011")
	validFor   = flag.Duration("duration", 365*24*time.Hour, "Duration that certificate is valid for")
	isCA       = flag.Bool("ca", false, "whether this cert should be its own Certificate Authority")
	rsaBits    = flag.Int("rsa-bits", 2048, "Size of RSA key to generate. Ignored if --ecdsa-curve is set")
	ecdsaCurve = flag.String("ecdsa-curve", "", "ECDSA curve to use to generate a key. Valid values are P224, P256 (recommended), P384, P521")
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

	derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil{
		fmt.Println(err)
	}
	certBlock := pem.Block{Type: "CERTIFICATE", Bytes: derBytes}

	log.Println("Generated cert.")
	certification = EncodeCert(fmt.Sprintf("", HashSHA1(derBytes)))

	return generateJson() , pem.EncodeToMemory(&privateKeyBlock), pem.EncodeToMemory(&certBlock)
}

func generateKeys() {
	p, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("failed to generate private key: %s\n", err)
	}
	priv = p
	log.Println("Generated keys.")
}

func generateJson() JwksJson {
	var privKeyMap = map[string]interface{}{}
	privKeyMap["alg"] = "RS256"
	privKeyMap["use"] = "sig"
	privKeyMap["kid"] = certification
	privKeyMap["kty"] = "RSA"
	privKeyMap["e"] = safeEncode(big.NewInt(int64(priv.PublicKey.E)).Bytes())
	privKeyMap["n"] = safeEncode(priv.N.Bytes())
	//privKeyMap["n"] = safeEncode(getNFromKey(priv).Bytes())
	return AddKey(privKeyMap)
}
