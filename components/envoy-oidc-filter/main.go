package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/cellery-io/mesh-security/components/envoy-oidc-filter/oidc"
	ext_authz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2alpha"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	IdpDiscoveryUrlEnv         = "IDP_DISCOVERY_URL"
	SkipDiscoveryCertVerifyEnv = "SKIP_DISCOVERY_URL_CERT_VERIFY"
	ClientIdEnv                = "CLIENT_ID"
	ClientSecretEnv            = "CLIENT_SECRET"
	RedirectUrlEnv             = "REDIRECT_URL"
	AppUrlEnv                  = "APP_BASE_URL"
	DcrEpEnv                   = "DCR_ENDPOINT"
	DcrUser                    = "DCR_USER"
	DcrPassword                = "DCR_PASSWORD"
	PrivateKeyFile             = "PRIVATE_KEY_FILE"
	CertificateFile            = "CERTIFICATE_FILE"
	JwtIssuer                  = "JWT_ISSUER"
	JwtAudience                = "JWT_AUDIENCE"
)

func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt)

	_, skipCertVerify := os.LookupEnv(SkipDiscoveryCertVerifyEnv)
	if skipCertVerify {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	cfg := &oidc.Config{
		Provider:        os.Getenv(IdpDiscoveryUrlEnv),
		ClientID:        os.Getenv(ClientIdEnv),
		ClientSecret:    os.Getenv(ClientSecretEnv),
		RedirectURL:     os.Getenv(RedirectUrlEnv),
		BaseURL:         os.Getenv(AppUrlEnv),
		DcrEP:           os.Getenv(DcrEpEnv),
		DcrUser:         os.Getenv(DcrUser),
		DcrPassword:     os.Getenv(DcrPassword),
		PrivateKeyFile:  os.Getenv(PrivateKeyFile),
		CertificateFile: os.Getenv(CertificateFile),
		JwtIssuer:       os.Getenv(JwtIssuer),
		JwtAudience:     os.Getenv(JwtAudience),
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
