package main

import (
	"fmt"
	"github.com/cellery-io/mesh-security/components/envoy-oidc-filter/oidc"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2alpha"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
)

func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	cfg := &oidc.Config{
		Provider:     "https://accounts.google.com",
		ClientID:     ":)",
		ClientSecret: ":)",
		RedirectURL:  "http://my-domain.com/_auth/callback",
		BaseURL:      "http://my-domain.com/pet/",
	}

	auth, err := oidc.NewAuthenticator(cfg)
	if err != nil {
		log.Fatal(err)
	}

	// Start auth callback http server
	go func() {
		mux := http.NewServeMux()
		mux.HandleFunc("/_auth/callback", auth.Callback)
		fmt.Printf("Starting HTTP auth callback reciver on %q\n", "8990")
		log.Fatal(http.ListenAndServe(":8990", mux))
	}()

	// Start auth check envoy gRPC filter
	go func() {
		s := grpc.NewServer()
		ext_authz.RegisterAuthorizationServer(s, auth)
		reflection.Register(s)

		fmt.Printf("Starting gRPC filter reciver on %q\n", "8081")
		lis, err := net.Listen("tcp", ":8081")
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		log.Fatal(s.Serve(lis))
	}()
	<-c
}
