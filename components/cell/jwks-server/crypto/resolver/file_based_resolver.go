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
	"crypto/x509"
	"encoding/pem"
	"log"
)

const KeyFilePath string = "/etc/certs/key.pem"
const CertFilePath string = "/etc/certs/cert.pem"

func FileBasedKeyResolver(privateKeyStr []byte, certificateStr []byte) error{
	blockPriv, _ := pem.Decode([]byte(privateKeyStr))
	//To get RSA Private key
	key, errKey := x509.ParsePKCS1PrivateKey(blockPriv.Bytes)
	if errKey != nil {
		log.Printf("Error parsing private key. %s\n", errKey)
		return errKey
	}

	blockCert, _ := pem.Decode([]byte(certificateStr))
	//To obtain a single certificate from the given ASN.1 DER data.
	cert, errCert := x509.ParseCertificate(blockCert.Bytes)
	if errCert != nil {
		log.Printf("Error parsing certificate. %s\n", errKey)
		return errCert
	}
	log.Println("Decoded and parsed key and cert.")
	certification := ""
	if cert == nil{
		log.Println("Unable to find the cert.")
		return nil
	}
	certification = EncodeCert(cert.Raw)
	generateJson(certification, key.PublicKey)
	return nil
}


