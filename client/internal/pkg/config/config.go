package config

import (
	"errors"
)

type Config interface {
	Save() error
	Oidc() ClientOIDCConfig
	CertificateAuthorityURL() string
	HasPrivateKey() bool
	GetPrivateKeyBytes() ([]byte, error)
	SetPrivateKeyBytes(pemBytes []byte) error
	GetPublicKeyBytes() ([]byte, error)
	GetCertificateBytes() ([]byte, error)
	SetCertificateBytes(pemBytes []byte) error
	GetRefreshToken() (string, error)
	SetRefreshToken(token string) error
}
type ClientOIDCConfig struct {
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	RedirectURL string   `json:"redirect_url"`
}

type SystemConfig struct {
	Issuer                  string   `json:"issuer"`
	ClientID                string   `json:"client_id"`
	Scopes                  []string `json:"scopes"`
	RedirectURL             string   `json:"redirect_url"`
	CertificateAuthorityURL string   `json:"ca_url"`
}

var (
	ErrNoPrivateKey  = errors.New("no private key found")
	ErrNoCertificate = errors.New("no certificate found")
)
