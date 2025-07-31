package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/protect"
	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"
)

type ClientConfig struct {
	name string
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

func LoadConfig(name string) (*ClientConfig, error) {
	y, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	config := &ClientConfig{name: name}
	if err := yaml.Unmarshal(y, config); err != nil {
		return nil, fmt.Errorf("problem parsing config: %w", err)
	}

	return config, nil
}

func (c *ClientConfig) Save() error {
	name, err := func() (string, error) {
		// save to a temp file first
		t, err := os.CreateTemp(filepath.Dir(c.name), "config*")
		if err != nil {
			// creation failed
			return "", err
		}
		defer t.Close()

		// marshal yaml
		y, err := yaml.Marshal(c)
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

	// ensure file is removed it it was created
	if name != "" {
		defer os.Remove(name)
	}

	// check save was ok
	if err != nil {
		return err
	}

	// move into place
	return os.Rename(c.name, name)
}

func (c *ClientConfig) HasPrivateKey() bool {
	return c.Ssh.PrivateKey != nil
}

func (c *ClientConfig) GetPrivateKeyBytes() ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// unprotect key
	pemBytes, err := protect.Decrypt(c.Ssh.PrivateKey, "key")
	if err != nil {
		return nil, err
	}

	return pemBytes, nil
}

func (c *ClientConfig) SetPrivateKeyBytes(pemBytes []byte) error {
	protected, err := protect.Encrypt(pemBytes, "key")
	if err != nil {
		return err
	}

	c.Ssh.PrivateKey = protected

	// save config
	if err := c.Save(); err != nil {
		return err
	}

	return nil
}

func (c *ClientConfig) GetPublicKeyBytes() ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// get key
	pemBytes, err := c.GetPrivateKeyBytes()
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

func (c *ClientConfig) GetCertificateBytes() ([]byte, error) {
	if c.Ssh.Certificate == nil {
		return nil, ErrNoCertificate
	}

	return c.Ssh.Certificate, nil
}

func (c *ClientConfig) SetCertificateBytes(pemBytes []byte) error {
	c.Ssh.Certificate = pemBytes

	// save config
	if err := c.Save(); err != nil {
		return err
	}

	return nil
}

func (c *ClientConfig) GetRefreshToken() (string, error) {
	if c.Oidc.RefreshToken == nil {
		return "", ErrNoCertificate
	}

	// unprotect token
	token, err := protect.Decrypt(c.Oidc.RefreshToken, "token")
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func (c *ClientConfig) SetRefreshToken(token string) error {
	protected, err := protect.Encrypt([]byte(token), "token")
	if err != nil {
		return err
	}

	c.Oidc.RefreshToken = protected

	// save config
	if err := c.Save(); err != nil {
		return err
	}

	return nil
}
