package jwks

import (
	"encoding/json"
	"github.com/cellery-io/mesh-security/components/cell/jwks-server/jwks/keyResolvers"
	"github/gorilla/mux"
	"log"
	"net/http"
)

const httpPort string = ":8186"

func UnSecuredService() {
	router := mux.NewRouter()
	log.Println("Http Server initialized on Port " + httpPort + "...")
	router.HandleFunc("/jwks", getJson).Methods("GET")
	log.Fatal(http.ListenAndServe(httpPort, router))
}


func getJson(w http.ResponseWriter, r *http.Request) {
	jwksJson, _,_ := keyResolvers.GetKeys()
	err := json.NewEncoder(w).Encode(jwksJson)
	if err != nil {
		log.Println("Unable to encode the json. %s", err)
	}
}
