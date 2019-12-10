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
	"net/url"
	"path"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/envoyproxy/go-control-plane/envoy/api/v2/core"
	extauthz "github.com/envoyproxy/go-control-plane/envoy/service/auth/v2"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type"
	googlerpc "github.com/gogo/googleapis/google/rpc"
	"github.com/gogo/protobuf/types"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	IdTokenCookie  = "idtoken"
	RedirectCookie = "redirect"
	xInstanceId    = "x-instance-id"
)

type Authenticator struct {
	provider     *oidc.Provider
	providerInfo *providerInfo
	oauth2Config *oauth2.Config
	oidcConfig   *oidc.Config
	config       *Config
	ctx          context.Context
	cert         *x509.Certificate
	key          *rsa.PrivateKey
}

func NewAuthenticator(c *Config) (*Authenticator, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, c.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to get provider: %v", err)
	}

	providerInfo, err := loadProviderInfo(ctx, c.Provider)
	if err != nil {
		return nil, fmt.Errorf("failed to load provider info: %v", err)
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
		providerInfo: providerInfo,
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

	if isDefined(a.config.NonSecurePaths) {
		// non secured URLs are provided, skip authentication
		if isPathMatchFound(req.URL.Path, a.config.NonSecurePaths) {
			return validateCookieForNonSecuredPaths(req, a)
		} else {
			return checkAndPromptAuth(req, a)
		}
	} else if isDefined(a.config.SecurePaths) {
		// secure URLs are provided, only secure those
		if isPathMatchFound(req.URL.Path, a.config.SecurePaths) {
			return checkAndPromptAuth(req, a)
		} else {
			return validateCookieForNonSecuredPaths(req, a)
		}
	} else {
		// by default, consider everything as secured
		return checkAndPromptAuth(req, a)
	}
}

func validateCookieForNonSecuredPaths(req *http.Request, a *Authenticator) (*extauthz.CheckResponse, error) {

	if cookie, err := req.Cookie(IdTokenCookie); err == nil {
		fmt.Println("Validating cookie for non secured path since cookie is present")
		_, err := a.provider.Verifier(a.oidcConfig).Verify(a.ctx, cookie.Value)
		if err != nil {
			log.Printf("Error while validating token for non secured path. Hence ignoring error: %v", err)
			return buildOkCheckResponseWithoutAuthAndSub(), nil
		} else {
			token, sub, subHash, err := a.buildForwardHeaders(cookie.Value)
			if err != nil {
				fmt.Println(err)
				return buildServerErrorCheckResponse(), nil
			}
			return buildOkCheckResponse(fmt.Sprintf("Bearer %s", token), sub, subHash), nil
		}
	}
	return buildOkCheckResponseWithoutAuthAndSub(), nil
}

func checkAndPromptAuth(req *http.Request, a *Authenticator) (*extauthz.CheckResponse, error) {
	if cookie, err := req.Cookie(IdTokenCookie); err == nil {
		_, err := a.provider.Verifier(a.oidcConfig).Verify(a.ctx, cookie.Value)
		if err != nil {
			log.Println(err)
			return buildRedirectCheckResponse(req.URL.String(), a.authCodeURL()), nil
		} else {
			token, sub, subHash, err := a.buildForwardHeaders(cookie.Value)
			if err != nil {
				fmt.Println(err)
				return buildServerErrorCheckResponse(), nil
			}
			return buildOkCheckResponse(fmt.Sprintf("Bearer %s", token), sub, subHash), nil
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
		Name:     IdTokenCookie,
		Value:    rawIDToken,
		Path:     "/",
		HttpOnly: true,
	})

	if c, err := r.Cookie(RedirectCookie); err == nil {
		http.Redirect(w, r, c.Value, http.StatusFound)
	} else {
		http.Redirect(w, r, a.config.BaseURL, http.StatusFound)
	}
}

func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) {
	for _, cookie := range r.Cookies() {
		fmt.Println("Found a cookie named:", cookie.Name)
	}

	http.SetCookie(w, &http.Cookie{
		Name:   IdTokenCookie,
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	if len(a.config.LogoutURL) > 0 {
		http.Redirect(w, r, a.config.LogoutURL, http.StatusFound)
	} else {
		if len(a.providerInfo.EndSessionUrl) == 0 {
			http.Redirect(w, r, a.config.BaseURL, http.StatusFound)
		} else {
			idToken := ""
			if cookie, err := r.Cookie(IdTokenCookie); err == nil {
				idToken = cookie.Value
			}
			v := url.Values{
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {a.config.BaseURL},
				"state":                    {"state"},
			}
			redirectUrl := fmt.Sprintf("%s?%s", a.providerInfo.EndSessionUrl, v.Encode())
			http.Redirect(w, r, redirectUrl, http.StatusFound)
		}
	}
}

func isPathMatchFound(requestPath string, pathsToBeMatched []string) bool {
	for _, pathToMatch := range pathsToBeMatched { // check if an absolute path. ex: /pet or /pet/
		if !strings.HasSuffix(pathToMatch, "*") {
			if path.Clean(requestPath) == path.Clean(pathToMatch) {
				//fmt.Println("***** pattern: " + pathToMatch)
				//fmt.Println("***** matched request path: " + path.Clean(requestPath))
				return true
			}
		} else {
			// request path is a pattern suffixed with '*'. ex.: /pet/*
			// remove suffix '*' and try to match
			pathWithouthoutTrailingStar := strings.TrimSuffix(pathToMatch, "*")
			pathToMatchLength := len(pathWithouthoutTrailingStar)
			// check if the length of the path to match is lesser than or equal to the request path.
			// If not, can't compare.
			if pathToMatchLength <= len(requestPath) {
				if path.Clean(requestPath[:pathToMatchLength]) == path.Clean(pathWithouthoutTrailingStar) {
					//fmt.Println("***** pattern: " + pathToMatch)
					//fmt.Println("***** matched request path segment: " + path.Clean(requestPath[:pathToMatchLength]))
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

func (a *Authenticator) buildForwardHeaders(idToken string) (string, string, int, error) {

	tok, err := jwt.ParseSigned(idToken)
	if err != nil {
		return "", "", -1, err
	}
	c := jwt.Claims{}
	m := make(map[string]interface{})
	if err := tok.UnsafeClaimsWithoutVerification(&c, &m); err != nil {
		return "", "", -1, err
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
		return "", "", -1, err
	}
	//fmt.Println(newJwt)
	return newJwt, subHeaderValue, hash(subHeaderValue), nil
}

func toHttpRequest(checkReq *extauthz.CheckRequest) (*http.Request, error) {
	httpAttr := checkReq.Attributes.Request.Http
	method := httpAttr.Method
	uri := fmt.Sprintf("http://%s%s", httpAttr.Host, httpAttr.Path)
	req, err := http.NewRequest(method, uri, nil)
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
			OkResponse: &extauthz.OkHttpResponse{},
		},
	}
}

func buildOkCheckResponse(authzHeader string, xSubjectHeader string, subjectHash int) *extauthz.CheckResponse {
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
					{
						Header: &core.HeaderValue{
							Key:   xInstanceId,
							Value: getInstance(subjectHash),
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

func getInstance(val int) string {
	if val%2 == 0 {
		return "1"
	} else {
		return "2"
	}
}

func hash(s string) int {
	hashVal := 7
	for _, r := range s {
		hashVal = hashVal*31 + int(r)
	}
	return hashVal
}
