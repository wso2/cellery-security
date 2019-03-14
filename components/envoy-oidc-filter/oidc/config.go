package oidc

import "github.com/pkg/errors"

type Config struct {
	Provider        string
	DcrEP           string
	DcrUser         string
	DcrPassword     string
	ClientID        string
	ClientSecret    string
	RedirectURL     string
	BaseURL         string
	CertificateFile string
	PrivateKeyFile  string
	JwtIssuer       string
	JwtAudience     string
}

func (c *Config) Validate() error {
	if isEmpty(c.Provider) {
		return createErr("Identity provider not found in OIDC config")
	}
	if isEmpty(c.ClientID) {
		return createErr("Client id not found in OIDC config")
	}
	if isEmpty(c.ClientSecret) {
		// check if DCR configs are provided
		if isEmpty(c.DcrEP) || isEmpty(c.DcrUser) || isEmpty(c.DcrPassword) {
			return createErr("Either Client Id & Client Secret or DCR endpoint & credentials should be provided in OIDC config")
		}
	}
	if isEmpty(c.RedirectURL) {
		return createErr("Redirect Url not found in OIDC config")
	}
	if isEmpty(c.BaseURL) {
		return createErr("Base Url not found in OIDC config")
	}

	if isEmpty(c.PrivateKeyFile) || isEmpty(c.CertificateFile) {
		return createErr("private key file path cannot be empty")
	}

	if isEmpty(c.CertificateFile) {
		return createErr("certificate file path cannot be empty")
	}

	if isEmpty(c.JwtIssuer) {
		return createErr("jwt issuer cannot be empty")
	}

	if isEmpty(c.JwtAudience) {
		return createErr("jwt audience cannot be empty")
	}

	return nil
}

func isEmpty(str string) bool {
	return len(str) == 0
}

func createErr(err string) error {
	return errors.New(err)
}
