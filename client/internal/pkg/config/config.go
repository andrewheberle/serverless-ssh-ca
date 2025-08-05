package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/protect"
	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"
)

type Config struct {
	name   string
	mu     sync.RWMutex
	config ClientConfig
}
type ClientConfig struct {
	Oidc ClientOIDCConfig `json:"oidc"`
	Ssh  ClientSSHConfig  `json:"ssh"`
}

type ClientOIDCConfig struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	Scopes       []string `json:"scopes"`
	AccessType   string   `json:"access_type,omitempty"`
	RedirectURL  string   `json:"redirect_url"`
	RefreshToken []byte   `json:"refresh_token,omitempty"`
}

type ClientSSHConfig struct {
	CertificateAuthorityURL string `json:"ca_url"`
	PrivateKey              []byte `json:"private_key,omitempty"`
	Certificate             []byte `json:"certificate,omitempty"`
}

var (
	ErrNoPrivateKey  = errors.New("no private key found")
	ErrNoCertificate = errors.New("no certificate found")
)

func LoadConfig(name string) (*Config, error) {
	y, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	var config ClientConfig
	if err := yaml.Unmarshal(y, &config); err != nil {
		return nil, fmt.Errorf("problem parsing config: %w", err)
	}

	return &Config{
		name:   name,
		config: config,
	}, nil
}

func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.save()
}

func (c *Config) save() error {
	temp, err := func() (string, error) {
		// save to a temp file first
		t, err := os.CreateTemp(filepath.Dir(c.name), "config*")
		if err != nil {
			// creation failed
			return "", err
		}
		defer func() {
			_ = t.Close()
		}()

		// marshal yaml
		y, err := yaml.Marshal(c.config)
		if err != nil {
			return t.Name(), err
		}

		// write config
		if _, err := t.Write(y); err != nil {
			return t.Name(), err
		}

		// return name and no error
		return t.Name(), nil
	}()

	// ensure temp file is removed it it was created
	if temp != "" {
		defer func() {
			_ = os.Remove(temp)
		}()
	}

	// check save to temp was ok
	if err != nil {
		return err
	}

	// move into place
	return os.Rename(temp, c.name)
}

func (c *Config) Oidc() ClientOIDCConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.config.Oidc
}

func (c *Config) CertificateAuthorityURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.config.Ssh.CertificateAuthorityURL
}

func (c *Config) HasPrivateKey() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// get key
	pemBytes, err := c.getPrivateKeyBytes()
	if err != nil {
		return false
	}

	// parse key
	if _, err := ssh.ParsePrivateKey(pemBytes); err != nil {
		return false
	}

	return true
}

func (c *Config) GetPrivateKeyBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.getPrivateKeyBytes()
}

func (c *Config) getPrivateKeyBytes() ([]byte, error) {
	// unprotect key
	pemBytes, err := protect.Decrypt(c.config.Ssh.PrivateKey, "key")
	if err != nil {
		return nil, err
	}

	return pemBytes, nil
}

func (c *Config) SetPrivateKeyBytes(pemBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	protected, err := protect.Encrypt(pemBytes, "key")
	if err != nil {
		return err
	}

	// set key and also clear certificate
	c.config.Ssh.PrivateKey = protected
	c.config.Ssh.Certificate = nil

	// save config
	if err := c.save(); err != nil {
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

	// get key
	pemBytes, err := c.getPrivateKeyBytes()
	if err != nil {
		return nil, err
	}

	// parse key
	key, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	// return as public key
	return ssh.MarshalAuthorizedKey(key.PublicKey()), nil
}

func (c *Config) GetCertificateBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.config.Ssh.Certificate == nil {
		return nil, ErrNoCertificate
	}

	return c.config.Ssh.Certificate, nil
}

func (c *Config) SetCertificateBytes(pemBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.config.Ssh.Certificate = pemBytes

	// save config
	if err := c.save(); err != nil {
		return err
	}

	return nil
}

func (c *Config) GetRefreshToken() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.config.Oidc.RefreshToken == nil {
		return "", ErrNoCertificate
	}

	// unprotect token
	token, err := protect.Decrypt(c.config.Oidc.RefreshToken, "token")
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func (c *Config) SetRefreshToken(token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	protected, err := protect.Encrypt([]byte(token), "token")
	if err != nil {
		return err
	}

	c.config.Oidc.RefreshToken = protected

	// save config
	if err := c.save(); err != nil {
		return err
	}

	return nil
}
