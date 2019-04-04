package expose

import (
	"encoding/json"
	"github/gorilla/mux"
	"log"
	"net/http"
	"github.com/mesh-security/components/cell/jwks-server/main/expose/keyResolvers"
)

const httpPort string = ":8186"

func UnSecuredService() {
	router := mux.NewRouter()
	log.Println("Https Server started successfully on Port " + httpPort + "...")
	router.HandleFunc("/jwks", getJson).Methods("GET")
	log.Fatal(http.ListenAndServe(httpPort, router))
}


func getJson(w http.ResponseWriter, r *http.Request) {
	jwksJson, _,_ := keyResolvers.GetFileBasedKeys()
	err := json.NewEncoder(w).Encode(jwksJson)
	if err != nil {
		log.Println("Unable to encode the json. %s", err)
	}
}
