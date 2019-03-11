package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	extauthz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2alpha"
	"github.com/envoyproxy/go-control-plane/envoy/type"
	googlerpc "github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"golang.org/x/oauth2"
	"log"
	"net/http"
)

const (
	IdTokenCookie  = "idtoken"
	RedirectCookie = "redirect"
)

type Authenticator struct {
	provider       *oidc.Provider
	oauth2Config   *oauth2.Config
	oidcConfig     *oidc.Config
	config         *Config
	ctx            context.Context
	unsecuredPaths map[string]bool
}

func NewAuthenticator(c *Config) (*Authenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, c.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	config := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  c.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
	oidcConfig := &oidc.Config{
		ClientID: c.ClientID,
	}

	return &Authenticator{
		provider:     provider,
		oauth2Config: config,
		oidcConfig:   oidcConfig,
		ctx:          ctx,
		config:       c,
		unsecuredPaths: map[string]bool{
			"/pet/app/*": true,
			"/pet/":      true,
		},
	}, nil
}

func (a *Authenticator) Check(ctx context.Context, checkReq *extauthz.CheckRequest) (*extauthz.CheckResponse, error) {

	req, err := toHttpRequest(checkReq)

	if err != nil {
		log.Println(err)
	}

	//fmt.Println(path.Clean(req.URL.Path))
	//for k, _ := range a.unsecuredPaths {
	//	if matched, _ := path.Match(path.Clean(k), path.Clean(req.URL.Path)); matched {
	//		fmt.Printf("======= %s matched with url %s\n", k, req.URL.Path)
	//		return buildOkCheckResponse(), nil
	//	}
	//}

	if cookie, err := req.Cookie(IdTokenCookie); err == nil {
		_, err := a.provider.Verifier(a.oidcConfig).Verify(a.ctx, cookie.Value)
		if err != nil {
			log.Println(err)
			return buildRedirectCheckResponse(req.URL.String(), a.authCodeURL()), nil
		} else {
			return buildOkCheckResponse(), nil
		}
	} else {
		return buildRedirectCheckResponse(req.URL.String(), a.authCodeURL()), nil
	}
}

func (a *Authenticator) Callback(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		fmt.Println("Found a cookie named:", cookie.Name)
	}

	if r.URL.Query().Get("state") != "state" {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}
	token, err := a.oauth2Config.Exchange(a.ctx, r.URL.Query().Get("code"))
	if err != nil {
		log.Printf("no token found: %v", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	idToken, err := a.provider.Verifier(a.oidcConfig).Verify(a.ctx, rawIDToken)

	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage
	}{token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println(string(data))

	http.SetCookie(w, &http.Cookie{
		Name:  IdTokenCookie,
		Value: rawIDToken,
		Path:  "/",
	})

	if c, err := r.Cookie(RedirectCookie); err == nil {
		http.Redirect(w, r, c.Value, http.StatusFound)
	} else {
		http.Redirect(w, r, a.config.BaseURL, http.StatusFound)
	}
}

func (a *Authenticator) authCodeURL() string {
	return a.oauth2Config.AuthCodeURL("state")
}

func toHttpRequest(checkReq *extauthz.CheckRequest) (*http.Request, error) {
	httpAttr := checkReq.Attributes.Request.Http
	method := httpAttr.Method
	url := fmt.Sprintf("http://%s%s", httpAttr.Host, httpAttr.Path)
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range httpAttr.Headers {
		req.Header.Set(k, v)
	}
	return req, nil
}

func buildRedirectCheckResponse(currentUrl string, redirectUrl string) *extauthz.CheckResponse {

	c := http.Cookie{
		Name:  RedirectCookie,
		Value: currentUrl,
		Path:  "/",
	}
	return &extauthz.CheckResponse{
		Status: &googlerpc.Status{Code: int32(googlerpc.UNAUTHENTICATED)},
		HttpResponse: &extauthz.CheckResponse_DeniedResponse{
			DeniedResponse: &extauthz.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_Found,
				},
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "Location",
							Value: redirectUrl,
						},
						Append: &types.BoolValue{
							Value: false,
						},
					},
					{
						Header: &core.HeaderValue{
							Key:   "Set-Cookie",
							Value: c.String(),
						},
						Append: &types.BoolValue{
							Value: false,
						},
					},
				},
			},
		},
	}
}

func buildOkCheckResponse() *extauthz.CheckResponse {
	return &extauthz.CheckResponse{
		Status: &googlerpc.Status{Code: int32(googlerpc.OK)},
	}
}
