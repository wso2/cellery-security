package oidc

type Config struct {
	Provider     string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	BaseURL      string
}

func (c *Config) Validate() error {
	return nil
}
