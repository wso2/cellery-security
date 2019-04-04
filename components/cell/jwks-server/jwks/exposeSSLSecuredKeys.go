package expose

import (
	"crypto/tls"
	"github.com/mesh-security/components/cell/jwks-server/main/expose/keyResolvers"
	"github.com/mesh-security/components/cell/jwks-server/main/expose/util"
	"log"
	"net/http"
)

const httpsPort string = ":8185"

func SSLSecuredService() {
	_, isErrorKey := keyResolvers.ReadFile(keyResolvers.KEY_FILE_PATH)
	_, isErrorCert := keyResolvers.ReadFile(keyResolvers.CERT_FILE_PATH)
	if (isErrorKey == false) && (isErrorCert == false) {
		log.Println("Https Server started successfully on Port " + httpsPort + "...")
		http.HandleFunc("/jwks", util.GetJwks)
		err := http.ListenAndServeTLS(httpsPort, keyResolvers.CERT_FILE_PATH, keyResolvers.KEY_FILE_PATH, nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	} else {
		log.Println("Unable to read from /etc/certs for https. Generating self signed keys.")
		generateSSLCertAndKey()
	}
}

func generateSSLCertAndKey(){
	jwksJson, keyB, certB := keyResolvers.GetGeneratedKeys()
	cert, err := tls.X509KeyPair(certB, keyB)
	if err != nil {
		log.Print("Mis match with the private key and public key. %s", err)
	}
	//Construct a tls.config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	log.Println("Generated key map :",jwksJson)
	log.Println("Https Server started successfully on Port "+ httpsPort +" ...")
	http.HandleFunc("/jwks", util.GetGeneratedJwks)

	server := http.Server{
		TLSConfig: tlsConfig,
		Addr:":8185",
	}
	log.Println("Reading cert and key for https...")
	err = server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}