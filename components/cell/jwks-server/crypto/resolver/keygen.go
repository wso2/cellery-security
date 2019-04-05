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
	"crypto/sha1"
	b64 "encoding/base64"
	"fmt"
	"log"
)

func EncodeCert(certBytes []byte) string {
	h := sha1.New()
	h.Write(certBytes)
	hashSum := h.Sum(nil)
	log.Println("Hash SHA1 sum generated.")
	sEnc := b64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%x", hashSum)))
	log.Println("Encoded to base 64.")
	return sEnc
}

type Json struct {
	Keys [] Key `json:"keys"`
}

type Key struct {
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	E string `json:"e"`
	N string `json:"n"`
}

