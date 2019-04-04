package keyResolvers

import (
	"crypto/sha1"
	b64 "encoding/base64"
	"log"
	"strings"
)

func HashSHA1(certBytes []byte) []byte {
	h := sha1.New()
	h.Write(certBytes)
	bs := h.Sum(nil)
	log.Println("Hash SHA1 sum generated.")
	return bs
}

func EncodeCert(hashCert string) string {
	sEnc := b64.RawStdEncoding.EncodeToString([]byte(hashCert))
	log.Println("Encoded to base 64.")
	return sEnc
}

type JwksJson struct {
	Keys []map[string]interface{} `json:"keys"`
}

func AddKey(jsonKey map[string]interface{}) JwksJson {
	finalJson := JwksJson{Keys: []map[string]interface{}{jsonKey}}
	return finalJson
}

func safeEncode(bytes []byte) string {
	data := b64.URLEncoding.EncodeToString(bytes)
	return strings.TrimRight(data, "=")
}
