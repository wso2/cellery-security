package keyResolvers

import (
	"crypto/rsa"
	"math/big"
)

func GenerateJson(certification string, publicKey rsa.PublicKey) JwksJson {
	var privKeyMap = map[string]interface{}{}
	privKeyMap["alg"] = "RS256"
	privKeyMap["use"] = "sig"
	privKeyMap["kid"] = certification
	privKeyMap["kty"] = "RSA"
	privKeyMap["e"] = safeEncode(big.NewInt(int64(publicKey.E)).Bytes())
	privKeyMap["n"] = safeEncode(publicKey.N.Bytes())
	return AddKey(privKeyMap)
}
