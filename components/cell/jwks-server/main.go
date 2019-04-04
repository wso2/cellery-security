package main

import "github.com/mesh-security/components/cell/jwks-server/main/expose"

func main (){
	go expose.SSLSecuredService()
	expose.UnSecuredService()
}
