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
	"crypto/tls"
	//"github.com/cellery-io/mesh-security/components/cell/jwks-server/crypto/service"
	"github.com/cellery-io/mesh-security/components/cell/jwks-server/resources"
	"io/ioutil"
	"log"
	"testing"
)

const keyFilePath string = "../../resources/key.pem"
const certFilePath string = "../../resources/cert.pem"

const kid = "OTFkOTUzMGIzYTc3YjFkMmRiNmJmOTA0NTk0OGRiNjVhODBkNDllNQ"
const kty = "RSA"
const alg = "RS256"
const e = "AQAB"
const use = "sig"
const n = "vsRPSm+Sr0+7ph95NrX8OCZzlUikl" +
	"zdH0LFBVB7HP1j50XQ9lSC+t79ffFcAc12SMcB6hKVC5vVUrNmC0Szcbik3DCrghYV311CqNEDwXGhqhVAmd6y+EJ5vgDHdB1uJjz2" +
	"0mBrYtbD9gr5hesuGXrOy473EZBBFmvLKOT2QdsoKnCyR2MJ6L5J+Muv87ow4FB8C9GXr4uMPcw8FMHse6NSHOZhTGkC2q3ve5jVun/" +
	"0w8m5Wze+2O1Gh56vPZ+e+7WF1uqh+Yfb83tJeJBoAskMdsSOi5tEdy/hP/A8QelNTpM1MmOYx0M03z2Cr5vooPRd15fRLhZO00sP+P" +
	"pfS0IaYgahQx8wBORcHoc0eZmG/m32EMvtLpfLk0e9edn5F8t/HNjVtM0SssneWm2BKTFn7ZmiKgW3mtLOPRKITpVtBG4Yorz44WDwcY" +
	"2FnD+7ftGeHcyRSUPvUELDooYDEiTWyFydeJ0RyIUTrMnMete0S+53B7h2dzy9I+iwY1o1V4ZbRVz5z0aCWi/QfhzRLY+4J7mOwdsYJo" +
	"yfMCPh8elGZIChQfFgaIY/Vnwm4yYqpQxb6QpTbKUZspkREkdwnU/Fr/xgi0gVOgf24qPZi0OJV2n9S8MXeQMSA4P1hpr9h9D+7qdc" +
	"DwDt6SGSO6W20jYk6TwKIZeqTEEg3bnDEsak"

func TestFileBasedKeyPair(t *testing.T) {
	keyData, err := ioutil.ReadFile(keyFilePath)
	certData, err := ioutil.ReadFile(certFilePath)

	if err != nil {
		log.Printf("Error reading the files %s, %s. %s", keyFilePath, certFilePath, err)
	}
	jwksJson, err := KeyResolver(keyData, certData)
	if err != nil {
		log.Printf("Unable to resolve the keys given. %s", err)
	}
	isValid := checkValues(jwksJson)

	if !isValid {
		t.Errorf("Expected json is not found in the output json.")
	}
}

func TestKeyGenerator(t *testing.T) {
	_, err := KeyGenerator()
	keyB, certB := GetKeyAndCertBytes()
	if err != nil {
		t.Errorf("Error occured in creating the self signed key pair.")
	}

	_, err = tls.X509KeyPair(certB, keyB)
	if err != nil {
		t.Errorf("Mismatch with the private key and public key.")
	}
}

func checkValues(keys resources.JwksJson) bool {
	var key = keys.Keys[0]
	if (key.Kid == kid) && (key.Kty == kty) && (key.Alg == alg) && (key.E == e) && (key.Use == use) &&
		(key.N == n) {
		return true
	} else {
		return false
	}
}
