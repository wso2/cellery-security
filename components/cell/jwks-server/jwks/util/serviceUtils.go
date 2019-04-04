package util

import (
	"encoding/json"
	"github.com/cellery-io/mesh-security/components/cell/jwks-server/jwks/keyResolvers"
	"log"
	"net/http"
)

func GetJwks(w http.ResponseWriter, r *http.Request) {
	jwksJson, _,_ := keyResolvers.GetKeys()
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

