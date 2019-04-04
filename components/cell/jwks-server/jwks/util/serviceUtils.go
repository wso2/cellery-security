package util

import (
	"encoding/json"
	"log"
	"net/http"
	"github.com/mesh-security/components/cell/jwks-server/main/expose/keyResolvers"
)

func GetJwks(w http.ResponseWriter, r *http.Request) {
	jwksJson, _,_ := keyResolvers.GetFileBasedKeys()
	err := json.NewEncoder(w).Encode(jwksJson)
	if err != nil {
		log.Println("Unable to encode the json. %s", err)
	}
}

func GetGeneratedJwks(w http.ResponseWriter, r *http.Request) {
	jwksJson, _,_ := keyResolvers.GetGeneratedKeys()
	log.Println("Generated the jwks.")
	err := json.NewEncoder(w).Encode(jwksJson)
	if err != nil {
		log.Println("Unable to encode the json. %s", err)
	}
}
