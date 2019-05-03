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
	"github.com/cellery-io/mesh-security/components/cell/jwks-server/resources"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
)

const (
	httpsDefaultPort int = 8185
	jwksPortEnvVar       = "jwksPort"
	certEnvVar           = "certFile"
	keyEnvVar            = "keyFile"

	keyFileDefaultPath  string = "/etc/certs/key.pem"
	certFileDefaultPath string = "/etc/certs/cert.pem"
)

var (
	httpsPortString   string
	jwksJson          resources.JwksJson
	jsonBytesResponse []byte
	keyFilePath       string
	certFilePath      string
)

func SSLSecuredService() error {
	httpsPortString = getEnvPort()
	resolveEnvFilePaths()
	keyData, certData, err := checkFiles()
	if err == nil {
		log.Println("Key file read from /etc/certs.")
		jwksJson, err = resolver.KeyResolver(keyData, certData)
		jsonBytesResponse, err = json.Marshal(jwksJson)
		if err != nil {
			log.Printf("Error occured while reloving keys with the file based key resolver. %s", err)
			return err
		}
		return initSSLFileBased()
	} else {
		log.Printf("Unable to read from %s and %s for https. Generating self signed keys.",
			certFilePath, keyFilePath)
		err := initSSLServiceSelfGen()
		if err != nil {
			log.Printf("Error occured while generating the key and the cert. %s", err)
			return err
		}
	}
	return nil
}

func initSSLFileBased() error {
	http.HandleFunc("", getGeneratedJwks)
	log.Println("Generated key map :", jwksJson)
	log.Printf("Https Server initialized on Port %s.", httpsPortString)
	err := http.ListenAndServeTLS(httpsPortString, certFilePath, keyFilePath, nil)
	if err != nil {
		log.Printf("Listen And Serve: %s", err)
		return err
	}
	return nil
}

func checkFiles() ([]byte, []byte, error) {
	keyData, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		return nil, nil, err
	}
	certData, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		return nil, nil, err
	}
	return keyData, certData, nil
}

func generateCert() (tls.Certificate, error) {
	keyJson, err := resolver.KeyGenerator()
	keyBytes, certBytes := resolver.GetKeyAndCertBytes()
	jwksJson = keyJson
	jsonBytesResponse, err = json.Marshal(jwksJson)
	if err != nil {
		log.Printf("Error occured while generating the keys. %s", err)
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		log.Printf("Mismatch with the private key and public key. %s", err)
		return tls.Certificate{}, err
	}
	return cert, err
}

func initSSLServiceSelfGen() error {
	cert, err := generateCert()
	// Construct a tls.config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	log.Println("Generated key map :", jwksJson)
	log.Printf("Https Serverv initialized on Port %s.", httpsPortString)
	http.HandleFunc("", getGeneratedJwks)
	server := http.Server{
		TLSConfig: tlsConfig,
		Addr:      httpsPortString,
	}
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
		log.Printf("Environment variable %s could not be found.", jwksPortEnvVar)
		return ":" + strconv.Itoa(httpsDefaultPort)
	} else {
		log.Printf("Reading from the environment varibale :%s.", jwksPortEnvVar)
		return ":" + port
	}
}

func resolveEnvFilePaths() {
	certFilePath = os.Getenv(certEnvVar)
	keyFilePath = os.Getenv(keyEnvVar)
	if len(certFilePath) == 0 || len(keyFilePath) == 0 {
		log.Printf("Reading from the environment variables %s and %s was found.", certEnvVar, keyEnvVar)
		certFilePath = certFileDefaultPath
		keyFilePath = keyFileDefaultPath
	}
}

func getGeneratedJwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status, err := w.Write(jsonBytesResponse)
	if err != nil {
		log.Printf("Unable to encode the json. %s", err)
		w.WriteHeader(status)
	}
}
