package keyResolvers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
)

const KeyFilePath string = "/etc/certs/key.pem"
const CertFilePath string = "/etc/certs/cert.pem"

func FileBasedKeyReolver(privateKeyStr string, certificateStr string) JwksJson {
	blockPriv, _ := pem.Decode([]byte(privateKeyStr))
	//To get RSA Private key
	key, errKey := x509.ParsePKCS1PrivateKey(blockPriv.Bytes)
	if errKey != nil {
		log.Printf("Error parsing private key. %s\n", errKey)
	}

	blockCert, _ := pem.Decode([]byte(certificateStr))
	//To obtain a single certificate from the given ASN.1 DER data.
	cert, errCert := x509.ParseCertificate(blockCert.Bytes)
	if errCert != nil {
		log.Printf("Error parsing certificate. %s\n", errKey)
	}
	log.Println("Decoded and parsed key and cert.")
	certification := EncodeCert(fmt.Sprintf("%x", HashSHA1(cert.Raw)))
	jwksJson := GenerateJson(certification, key.PublicKey)
	return jwksJson
}