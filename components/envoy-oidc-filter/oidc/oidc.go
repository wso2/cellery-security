package oidc

import (
	"context"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	extauthz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2alpha"
	"github.com/envoyproxy/go-control-plane/envoy/type"
	googlerpc "github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	"path"
	"strings"
)

const (
	IdTokenCookie  = "idtoken"
	RedirectCookie = "redirect"
)

type dcrErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type dcrSuccessResponse struct {
	ClientName   string `json:"client_name"`
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type Authenticator struct {
	provider       *oidc.Provider
	oauth2Config   *oauth2.Config
	oidcConfig     *oidc.Config
	config         *Config
	ctx            context.Context
	cert           *x509.Certificate
	key            *rsa.PrivateKey
}

func NewAuthenticator(c *Config) (*Authenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, c.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	key, err := loadPrivateKey(c.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}
	cert, err := loadX509Certificate(c.CertificateFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %v", err)
	}

	if isDcrRequired(c) {
		log.Println("DCR required")
		clientId, clientSecret, err := dcr(c)
		if err != nil {
			return nil, fmt.Errorf("Error in performing DCR: %v", err)
		}
		c.ClientID = clientId
		c.ClientSecret = clientSecret
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
		key:          key,
		cert:         cert,
	}, nil
}

func (a *Authenticator) Check(ctx context.Context, checkReq *extauthz.CheckRequest) (*extauthz.CheckResponse, error) {

	req, err := toHttpRequest(checkReq)

	if err != nil {
		log.Println(err)
	}

	// if this is an unsecured path, skip re-auth
	if a.config.NonSecurePaths != nil && isNonSecurePath(req.URL.Path, a.config.NonSecurePaths) {
		//fmt.Println("***** non secured path: " + req.URL.Path)
		return buildOkCheckResponseWithoutAuthAndSub(), nil
	}

	if cookie, err := req.Cookie(IdTokenCookie); err == nil {
		_, err := a.provider.Verifier(a.oidcConfig).Verify(a.ctx, cookie.Value)
		if err != nil {
			log.Println(err)
			return buildRedirectCheckResponse(req.URL.String(), a.authCodeURL()), nil
		} else {
			token, sub, err := a.buildForwardHeaders(cookie.Value)
			if err != nil {
				fmt.Println(err)
				return buildServerErrorCheckResponse(), nil
			}
			return buildOkCheckResponse(fmt.Sprintf("Bearer %s", token), sub), nil
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

func isNonSecurePath(requestPath string, nonSecuredPaths []string) bool {
	for _, nonSecPath := range nonSecuredPaths {
		// check if an absolute path. ex: /pet or /pet/
		if !strings.HasSuffix(nonSecPath, "*") {
			if path.Clean(requestPath) == path.Clean(nonSecPath) {
				//fmt.Println("***** pattern: " + nonSecPath)
				//fmt.Println("***** matched request path: " + path.Clean(requestPath))
				return true
			}
		} else {
			// request path is a pattern suffixed with '*'. ex.: /pet/*
			// remove suffix '*' and try to match
			pathWithouthoutTrailingStar := strings.TrimSuffix(nonSecPath, "*")
			nonSecPathLength := len(pathWithouthoutTrailingStar)
			// check if the length of the non secured path is lesser than or equal to the request path.
			// If not, can't compare.
			if nonSecPathLength <= len(requestPath) {
				if path.Clean(requestPath[:nonSecPathLength]) == path.Clean(pathWithouthoutTrailingStar) {
					//fmt.Println("***** pattern: " + nonSecPath)
					//fmt.Println("***** matched request path segment: " + path.Clean(requestPath[:nonSecPathLength]))
					return true
				}
			}
		}
	}
	return false
}

func (a *Authenticator) authCodeURL() string {
	return a.oauth2Config.AuthCodeURL("state")
}

func (a *Authenticator) buildForwardHeaders(idToken string) (string, string, error) {

	tok, err := jwt.ParseSigned(idToken)
	if err != nil {
		return "", "", err
	}
	c := jwt.Claims{}
	m := make(map[string]interface{})
	if err := tok.UnsafeClaimsWithoutVerification(&c, &m); err != nil {
		return "", "", err
	}

	c.Issuer = a.config.JwtIssuer
	c.Audience = []string{a.config.JwtAudience}

	if len(a.config.SubjectClaim) > 0 {
		if sub, ok := m[a.config.SubjectClaim].(string); ok {
			c.Subject = sub
		}
	}

	subHeaderValue := c.Subject

	kid := base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprintf("%x", sha1.Sum(a.cert.Raw))))
	rsaSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: a.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)

	newJwt, err := jwt.Signed(rsaSigner).Claims(m).Claims(c).CompactSerialize()
	if err != nil {
		return "", "", err
	}
	//fmt.Println(newJwt)
	return newJwt, subHeaderValue, nil
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

func buildServerErrorCheckResponse() *extauthz.CheckResponse {
	return &extauthz.CheckResponse{
		Status: &googlerpc.Status{Code: int32(googlerpc.INTERNAL)},
		HttpResponse: &extauthz.CheckResponse_DeniedResponse{
			DeniedResponse: &extauthz.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode_InternalServerError,
				},
				Body: "500 Internal Server Error",
			},
		},
	}
}

func buildOkCheckResponseWithoutAuthAndSub() *extauthz.CheckResponse {
	return &extauthz.CheckResponse{
		Status: &googlerpc.Status{Code: int32(googlerpc.OK)},
		HttpResponse: &extauthz.CheckResponse_OkResponse{
			OkResponse: &extauthz.OkHttpResponse{
			},
		},
	}
}

func buildOkCheckResponse(authzHeader string, xSubjectHeader string) *extauthz.CheckResponse {
	return &extauthz.CheckResponse{
		Status: &googlerpc.Status{Code: int32(googlerpc.OK)},
		HttpResponse: &extauthz.CheckResponse_OkResponse{
			OkResponse: &extauthz.OkHttpResponse{
				Headers: []*core.HeaderValueOption{
					{
						Header: &core.HeaderValue{
							Key:   "Authorization",
							Value: authzHeader,
						},
						Append: &types.BoolValue{
							Value: false,
						},
					},
					{
						Header: &core.HeaderValue{
							Key:   "x-cellery-auth-subject",
							Value: xSubjectHeader,
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
