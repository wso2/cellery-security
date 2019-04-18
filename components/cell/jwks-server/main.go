package main

import (
	"github.com/cellery-io/mesh-security/components/cell/jwks-server/crypto/service"
	"log"
)

func main (){
	go service.UnSecuredService()
	err := service.SSLSecuredService()
	if err != nil{
		log.Printf("Error occure while establishing the SLL service. %s", err)
	}
}

