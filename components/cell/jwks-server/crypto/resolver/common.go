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
	"crypto/rsa"
	b64 "encoding/base64"
	"math/big"
)

var Jwks Json

func generateJson(certification string, publicKey rsa.PublicKey) {
	var newKey = Key{
		Alg: "RS256",
		Use: "sig",
		Kid: certification,
		Kty: "RSA",
		E: b64.RawStdEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		N: b64.RawStdEncoding.EncodeToString(publicKey.N.Bytes()),
	}
	Jwks = Json{
		Keys : []Key{newKey},
	}
}
