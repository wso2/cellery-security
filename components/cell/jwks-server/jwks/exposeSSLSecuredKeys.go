package jwks

import (
	"crypto/tls"
	"github.com/cellery-io/mesh-security/components/cell/jwks-server/jwks/keyResolvers"
	"github.com/cellery-io/mesh-security/components/cell/jwks-server/jwks/util"
	"log"
	"net/http"
	"os"
)

const httpsDefaultPort string = ":8185"
const jwksPortEnvVar = "jwksPort"

var HttpsPort string

func SSLSecuredService() {
	HttpsPort = getEnvPort()
	_, isErrorKey := keyResolvers.ReadFile(keyResolvers.KeyFilePath)
	_, isErrorCert := keyResolvers.ReadFile(keyResolvers.CertFilePath)
	if (isErrorKey == false) && (isErrorCert == false) {
		log.Println("Https Server initialized on Port " + httpPort + ".")
		http.HandleFunc("/jwks", util.GetJwks)
		err := http.ListenAndServeTLS(HttpsPort, keyResolvers.CertFilePath, keyResolvers.KeyFilePath, nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	} else {
		log.Println("Unable to read from /etc/certs for https. Generating self signed keys.")
		generateSSLCertAndKey()
	}
}

func generateSSLCertAndKey() {
	jwksJson, keyB, certB := keyResolvers.GetGeneratedKeys()
	cert, err := tls.X509KeyPair(certB, keyB)
	if err != nil {
		log.Print("Mis match with the private key and public key. %s", err)
	}
	//Construct a tls.config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	log.Println("Generated key map :", jwksJson)
	log.Println("Https Server initialized on Port " + httpPort + ".")
	http.HandleFunc("/jwks", util.GetGeneratedJwks)

	server := http.Server{
		TLSConfig: tlsConfig,
		Addr:      HttpsPort,
	}
	log.Println("Reading cert and key for https...")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func getEnvPort() string {
	port := os.Getenv(jwksPortEnvVar)
	if len(port) == 0 {
		log.Println("Environment variable " + jwksPortEnvVar + " is not set.")
		return httpsDefaultPort
	} else {
		return ":" + os.Getenv(jwksPortEnvVar)
	}
}
