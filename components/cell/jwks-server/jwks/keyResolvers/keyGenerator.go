package keyResolvers

import (
	"crypto/sha1"
	b64 "encoding/base64"
	"log"
	"strings"
)

func HashSHA1(certBytes []byte) []byte {
	// The pattern for generating a hash is `sha1.New()`,
	// `sha1.Write(bytes)`, then `sha1.Sum([]byte{})`.
	// Here we start with a new hash.
	h := sha1.New()

	// `Write` expects bytes. If you have a string `s`,
	// use `[]byte(s)` to coerce it to bytes.
	h.Write(certBytes)

	// This gets the finalized hash result as a byte
	// slice. The argument to `Sum` can be used to append
	// to an existing byte slice: it usually isn't needed.
	bs := h.Sum(nil)

	// SHA1 values are often printed in hex, for example
	// in git commits. Use the `%x` format verb to convert
	// a hash results to a hex string.
	log.Println("Hash SHA1 sum generated.")
	return bs
}

func EncodeCert(hashCert string) string {
	// Go supports both standard and URL-compatible
	// base64. Here's how to encode using the standard
	// encoder. The encoder requires a `[]byte` so we
	// cast our `string` to that type.
	sEnc := b64.RawStdEncoding.EncodeToString([]byte(hashCert))
	log.Println("Encoded to base 64.")
	return sEnc
}

type JwksJson struct {
	Keys []map[string]interface{} `json:"keys"`
}

func AddKey(jsonKey map[string]interface{}) JwksJson {
	finalJson := JwksJson{Keys: []map[string]interface{}{jsonKey}}
	//fmt.Printf("%+v\n",finalJson)
	//fmt.Println(finalJson)
	return finalJson
}

func safeEncode(p []byte) string {
	data := b64.URLEncoding.EncodeToString(p)
	return strings.TrimRight(data, "=")
}
