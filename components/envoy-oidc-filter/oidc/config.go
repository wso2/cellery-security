package oidc

import "github.com/pkg/errors"

type Config struct {
	Provider     string
	DcrEP        string
	DcrUser      string
	DcrPassword  string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	BaseURL      string
}

func (c *Config) Validate() error {
	if IsEmpty(c.Provider)  {
		return createErr("Identity provider not found in OIDC config")
	}
	if IsEmpty(c.ClientID) {
		return createErr("Client id not found in OIDC config")
	}
	if IsEmpty(c.ClientSecret)  {
		// check if DCR configs are provided
		if IsEmpty(c.DcrEP) || IsEmpty(c.DcrUser) || IsEmpty(c.DcrPassword) {
			return createErr("Either Client Id & Client Secret or DCR endpoint & credentials should be provided in OIDC config")
		}
	}
	if IsEmpty(c.RedirectURL)  {
		return createErr("Redirect Url not found in OIDC config")
	}
	if IsEmpty(c.BaseURL)  {
		return createErr("Base Url not found in OIDC config")
	}
	return nil
}

func IsEmpty(str string) bool {
	return len(str) == 0
}

func createErr (err string) error {
	return errors.New(err)
}
