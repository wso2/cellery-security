package main

import "github.com/cellery-io/mesh-security/components/cell/jwks-server/jwks"

func main (){
	go jwks.SSLSecuredService()
	jwks.UnSecuredService()
}
