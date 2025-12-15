package config

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/protect"
	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/sshcert"
	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"
)

const FriendlyAppName = "Serverless SSH CA Client"

type Config struct {
	mu          sync.RWMutex
	system      SystemConfig
	user        UserConfig
	protector   protect.Protector
	persistence Persistence
}

type ClientOIDCConfig struct {
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	RedirectURL string   `json:"redirect_url"`
}

type SystemConfig struct {
	Issuer                      string   `json:"issuer"`
	ClientID                    string   `json:"client_id"`
	Scopes                      []string `json:"scopes"`
	RedirectURL                 string   `json:"redirect_url"`
	CertificateAuthorityURL     string   `json:"ca_url"`
	TrustedCertificateAuthority string   `json:"trusted_ca"`
	ca                          ssh.PublicKey
}

type UserConfig struct {
	Certificate  []byte `json:"certificate,omitempty"`
	RefreshToken []byte `json:"refresh_token,omitempty"`
	PrivateKey   []byte `json:"private_key,omitempty"`
}

type Persistence interface {
	Save(config UserConfig) error
}

var (
	ErrNoPrivateKey   = errors.New("no private key found")
	ErrNoCertificate  = errors.New("no certificate found")
	ErrNoRefreshToken = errors.New("no refresh token found")
)

func LoadConfig(system, user string) (*Config, error) {
	s, err := loadSystemConfig(system)
	if err != nil {
		return nil, err
	}

	u, err := loadUserConfig(user)
	if err != nil {
		return nil, err
	}

	return &Config{
		system:      s,
		user:        u,
		protector:   protect.NewDefaultProtector(),
		persistence: &YamlPersistence{name: user},
	}, nil
}

func LoadUserConfigOnly(name string) (*Config, error) {
	u, err := loadUserConfig(name)
	if err != nil {
		return nil, err
	}

	return &Config{
		user:        u,
		protector:   protect.NewDefaultProtector(),
		persistence: &YamlPersistence{name: name},
	}, nil
}

func loadUserConfig(name string) (UserConfig, error) {
	y, err := os.ReadFile(name)
	if err != nil {
		// the user config missing is not fatal
		if errors.Is(err, os.ErrNotExist) {
			return UserConfig{}, nil
		}

		// otherwise return the error
		return UserConfig{}, err
	}

	var config UserConfig
	if err := yaml.UnmarshalStrict(y, &config); err != nil {
		return UserConfig{}, fmt.Errorf("problem parsing user config: %w", err)
	}

	return config, nil
}

func (c *Config) Save() error {
	return c.persistence.Save(c.user)
}

func (c *Config) Oidc() ClientOIDCConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return ClientOIDCConfig{
		Issuer:      c.system.Issuer,
		ClientID:    c.system.ClientID,
		Scopes:      c.system.Scopes,
		RedirectURL: c.system.RedirectURL,
	}
}

func (c *Config) CertificateAuthorityURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.system.CertificateAuthorityURL
}

func (c *Config) HasPrivateKey() bool {
	// parse key via Signer
	if _, err := c.Signer(); err != nil {
		return false
	}

	return true
}

// GetPrivateKeyBytes returns a []byte slice that contains the users
// unencrypted SSH private key. It is up to the caller to ensure this is
// handled securely.
func (c *Config) GetPrivateKeyBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.getPrivateKeyBytes()
}

func (c *Config) getPrivateKeyBytes() ([]byte, error) {
	// error if not private key exists
	if c.user.PrivateKey == nil {
		return nil, ErrNoPrivateKey
	}

	// unprotect key
	pemBytes, err := c.protector.Decrypt(c.user.PrivateKey, keySecretName)
	if err != nil {
		return nil, err
	}

	return pemBytes, nil
}

// SetPrivateKeyBytes encrypts and persists the PEM private key []byte slice
// via [Persistence]
func (c *Config) SetPrivateKeyBytes(pemBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	protected, err := c.protector.Encrypt(pemBytes, keySecretName)
	if err != nil {
		return err
	}

	// set key and also clear certificate
	c.user.PrivateKey = protected
	c.user.Certificate = nil

	// save config
	if err := c.persistence.Save(c.user); err != nil {
		return err
	}

	return nil
}

func (c *Config) GetPublicKeyBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.getPublicKeyBytes()
}

func (c *Config) getPublicKeyBytes() ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// get and parse key
	key, err := c.signer()
	if err != nil {
		return nil, err
	}

	// return as public key
	return ssh.MarshalAuthorizedKey(key.PublicKey()), nil
}

func (c *Config) GetCertificateBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.user.Certificate == nil {
		return nil, ErrNoCertificate
	}

	return c.user.Certificate, nil
}

func (c *Config) HasCertificate() bool {
	_, err := c.GetCertificateBytes()
	return err == nil
}

func (c *Config) CertificateValid() bool {
	return c.CerificateExpiry().After(time.Now())
}

func (c *Config) CerificateExpiry() time.Time {
	certBytes, err := c.GetCertificateBytes()
	if err != nil {
		return time.Time{}
	}

	// parse the cert, errors mean invalid
	cert, err := sshcert.ParseCert(certBytes)
	if err != nil {
		return time.Time{}
	}

	return time.Unix(int64(cert.ValidBefore), 0)
}

func (c *Config) SetCertificateBytes(pemBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.user.Certificate = pemBytes

	// save config
	if err := c.persistence.Save(c.user); err != nil {
		return err
	}

	return nil
}

func (c *Config) GetRefreshToken() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.user.RefreshToken == nil {
		return "", ErrNoRefreshToken
	}

	// unprotect token
	token, err := c.protector.Decrypt(c.user.RefreshToken, tokenSecretName)
	if err != nil {
		return "", err
	}
	defer clearBytes(token)

	return string(token), nil
}

func (c *Config) SetRefreshToken(token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	protected, err := c.protector.Encrypt([]byte(token), tokenSecretName)
	if err != nil {
		return err
	}

	c.user.RefreshToken = protected

	// save config
	if err := c.persistence.Save(c.user); err != nil {
		return err
	}

	return nil
}

// Signer returns a ssh.Signer
func (c *Config) Signer() (ssh.Signer, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.signer()
}

// CertificateAuthority returns the CA PublicKey
func (c *Config) CertificateAuthority() ssh.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.system.CertificateAuthority()
}

func (c *Config) signer() (ssh.Signer, error) {
	// get key
	pemBytes, err := c.getPrivateKeyBytes()
	if err != nil {
		return nil, err
	}
	defer clearBytes(pemBytes)

	// parse key and return signer
	return ssh.ParsePrivateKey(pemBytes)
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (c *SystemConfig) CertificateAuthority() ssh.PublicKey {
	return c.ca
}
