package main

import (
	"crypto/tls"
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

const (
	idpDiscoveryUrlEnv         = "IDP_DISCOVERY_URL"
	skipDiscoveryCertVerifyEnv = "SKIP_DISCOVERY_URL_CERT_VERIFY"
	clientIdEnv                = "CLIENT_ID"
	clientSecretEnv            = "CLIENT_SECRET"
	redirectUrlEnv             = "REDIRECT_URL"
	appUrlEnv                  = "APP_BASE_URL"
	dcrEpEnv                   = "DCR_ENDPOINT"
	dcrUser                    = "DCR_USER"
	dcrPassword                = "DCR_PASSWORD"
)

func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	_, skipCertVerify := os.LookupEnv(skipDiscoveryCertVerifyEnv)
	if skipCertVerify {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	cfg := &oidc.Config{
		Provider:     os.Getenv(idpDiscoveryUrlEnv),
		ClientID:     os.Getenv(clientIdEnv),
		ClientSecret: os.Getenv(clientSecretEnv),
		RedirectURL:  os.Getenv(redirectUrlEnv),
		BaseURL:      os.Getenv(appUrlEnv),
		DcrEP:        os.Getenv(dcrEpEnv),
		DcrUser:      os.Getenv(dcrUser),
		DcrPassword:  os.Getenv(dcrPassword),
	}
	err := cfg.Validate()
	if err != nil {
		log.Fatal(err)
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
