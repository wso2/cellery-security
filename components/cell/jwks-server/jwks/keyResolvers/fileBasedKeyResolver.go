package keyResolvers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
)

const KEY_FILE_PATH string = "/etc/certs/key.pem"
const CERT_FILE_PATH string = "/etc/certs/cert.pem"

func FileBasedKeyReolver(privateKeyStr string, certificateStr string) JwksJson {
	blockPriv, _ := pem.Decode([]byte(privateKeyStr))
	key, errKey := x509.ParsePKCS1PrivateKey(blockPriv.Bytes)

	if errKey != nil {
		log.Printf("Error parsing private key. %s\n", errKey)
	}

	blockCert, _ := pem.Decode([]byte(certificateStr))
	cert, errCert := x509.ParseCertificate(blockCert.Bytes)

	if errCert != nil {
		log.Printf("Error parsing certificate. %s\n", errKey)
	}

	log.Println("Decoded and parsed key and cert.")

	certification := EncodeCert(fmt.Sprintf("%x", HashSHA1(cert.Raw)))
	//kid := b64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%x", sha1.Sum(cert.Raw))))
	jwksJson := generateFileBasedJson(certification, key.PublicKey)
	//fmt.Println(fmt.Sprintf("%+v\n",jwksJson))
	return jwksJson
}

func generateFileBasedJson(certification string, publicKey rsa.PublicKey) JwksJson {
	var privKeyMap = map[string]interface{}{}
	privKeyMap["alg"] = "RS256"
	privKeyMap["use"] = "sig"
	privKeyMap["kid"] = certification
	privKeyMap["kty"] = "RSA"
	privKeyMap["e"] = safeEncode(big.NewInt(int64(publicKey.E)).Bytes())
	privKeyMap["n"] = safeEncode(publicKey.N.Bytes())
	return AddKey(privKeyMap)
}
