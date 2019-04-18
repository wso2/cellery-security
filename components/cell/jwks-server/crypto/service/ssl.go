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

package service

import (
	"crypto/tls"
	"encoding/json"
	"github.com/cellery-io/mesh-security/components/cell/jwks-server/crypto/resolver"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

const httpsDefaultPort int = 8185
const jwksPortEnvVar = "jwksPort"

var HttpsPortString string

func SSLSecuredService() error{
	HttpsPortString = getEnvPort()
	keyData, keyError := ioutil.ReadFile(resolver.KeyFilePath)
	certData, certError := ioutil.ReadFile(resolver.CertFilePath)

	if keyError == nil && certError == nil{
		log.Println("Key file read from /etc/certs.")
		log.Println("Https Server initialized on Port " + string(HttpsPortString) + ".")
		log.Println("Key file read from /etc/certs.")

		err := resolver.FileBasedKeyResolver(keyData, certData)
		if err != nil {
			log.Printf("Error occured while reloving keys with the file based key resolver. %s", err)
			return err
		}
		http.HandleFunc("/jwks", getJwks)
		err = http.ListenAndServeTLS(HttpsPortString, resolver.CertFilePath, resolver.KeyFilePath, nil)
		if err != nil {
			log.Printf("Listen And Serve: %s", err)
			return err
		}
	} else {
		log.Println("Unable to read from /etc/certs for https. Generating self signed keys.")
		err := processSSLCertAndKey()
		if err != nil {
			log.Printf("Error occured while generating the key and the cert. %s", err)
			return err
		}
	}
	return nil
}

func processSSLCertAndKey() error{
	err := resolver.KeyGenerator()
	if err != nil {
		log.Printf("Error occured while generating the keys. %s" , err)
	}

	keyB := resolver.PrivateKey
	certB := resolver.Cert
	cert, err := tls.X509KeyPair(certB, keyB)
	if err != nil {
		log.Printf("Mis match with the private key and public key. %s", err)
	}
	//Construct a tls.config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	log.Println("Generated key map :", resolver.Jwks)
	log.Println("Https Server initialized on Port " + string(HttpsPortString) + ".")
	http.HandleFunc("/jwks", getGeneratedJwks)

	server := http.Server{
		TLSConfig: tlsConfig,
		Addr:      HttpsPortString,
	}
	log.Println("Reading cert and key for https...")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Printf("Listen And Serve: %s", err)
		return err
	}
	return nil
}

func getEnvPort() string {
	port := os.Getenv(jwksPortEnvVar)
	if len(port) == 0 {
		log.Println("Environment variable " + jwksPortEnvVar + " is not set.")
		return ":" + string(httpsDefaultPort)
	} else {
		return ":" + os.Getenv(jwksPortEnvVar)
	}
}

func getGeneratedJwks(w http.ResponseWriter, r *http.Request) {
	log.Println("Generated the jwks.")
	err := json.NewEncoder(w).Encode(resolver.Jwks)
	if err != nil {
		log.Printf("Unable to encode the json. %s", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func getJwks(w http.ResponseWriter, r *http.Request) {
	log.Println("Generated the jwks.")
	err := json.NewEncoder(w).Encode(resolver.Jwks)
	if err != nil {
		log.Printf("Unable to encode the json. %s", err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}