package user

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/protect"
	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"
)

var _ config.Config = (*User)(nil)

type User struct {
	mu               sync.RWMutex
	systemConfigName string
	system           SystemConfig
	userConfigName   string
	user             UserConfig
}

type SystemConfig struct {
	Issuer                  string   `json:"issuer"`
	ClientID                string   `json:"client_id"`
	Scopes                  []string `json:"scopes"`
	RedirectURL             string   `json:"redirect_url"`
	CertificateAuthorityURL string   `json:"ca_url"`
}

type UserConfig struct {
	Certificate  []byte `json:"certificate,omitempty"`
	RefreshToken []byte `json:"refresh_token,omitempty"`
	PrivateKey   []byte `json:"private_key,omitempty"`
}

func LoadConfig(system, user string) (*User, error) {
	s, err := loadSystemConfig(system)
	if err != nil {
		return nil, err
	}

	u, err := loadUserConfig(user)
	if err != nil {
		return nil, err
	}

	return &User{
		systemConfigName: system,
		system:           s,
		userConfigName:   user,
		user:             u,
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
	if err := yaml.Unmarshal(y, &config); err != nil {
		return UserConfig{}, fmt.Errorf("problem parsing user config: %w", err)
	}

	return config, nil
}

func (c *User) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.save()
}

// this saves the user part of the config
func (c *User) save() error {
	temp, err := func() (string, error) {
		// save to a temp file first
		t, err := os.CreateTemp(filepath.Dir(c.userConfigName), "user*")
		if err != nil {
			// creation failed
			return "", err
		}
		defer func() {
			_ = t.Close()
		}()

		// marshal yaml
		y, err := yaml.Marshal(c.user)
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
	return os.Rename(temp, c.userConfigName)
}

func (c *User) Oidc() config.ClientOIDCConfig {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return config.ClientOIDCConfig{
		Issuer:      c.system.Issuer,
		ClientID:    c.system.ClientID,
		Scopes:      c.system.Scopes,
		RedirectURL: c.system.RedirectURL,
	}
}

func (c *User) CertificateAuthorityURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.system.CertificateAuthorityURL
}

func (c *User) HasPrivateKey() bool {
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

func (c *User) GetPrivateKeyBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.getPrivateKeyBytes()
}

func (c *User) getPrivateKeyBytes() ([]byte, error) {
	// unprotect key
	pemBytes, err := protect.Decrypt(c.user.PrivateKey, "key")
	if err != nil {
		return nil, err
	}

	return pemBytes, nil
}

func (c *User) SetPrivateKeyBytes(pemBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	protected, err := protect.Encrypt(pemBytes, "key")
	if err != nil {
		return err
	}

	// set key and also clear certificate
	c.user.PrivateKey = protected
	c.user.Certificate = nil

	// save config
	if err := c.save(); err != nil {
		return err
	}

	return nil
}

func (c *User) GetPublicKeyBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.getPublicKeyBytes()
}

func (c *User) getPublicKeyBytes() ([]byte, error) {
	if !c.HasPrivateKey() {
		return nil, config.ErrNoPrivateKey
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

func (c *User) GetCertificateBytes() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.user.Certificate == nil {
		return nil, config.ErrNoCertificate
	}

	return c.user.Certificate, nil
}

func (c *User) SetCertificateBytes(pemBytes []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.user.Certificate = pemBytes

	// save config
	if err := c.save(); err != nil {
		return err
	}

	return nil
}

func (c *User) GetRefreshToken() (string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.user.RefreshToken == nil {
		return "", config.ErrNoCertificate
	}

	// unprotect token
	token, err := protect.Decrypt(c.user.RefreshToken, "token")
	if err != nil {
		return "", err
	}

	return string(token), nil
}

func (c *User) SetRefreshToken(token string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	protected, err := protect.Encrypt([]byte(token), "token")
	if err != nil {
		return err
	}

	c.user.RefreshToken = protected

	// save config
	if err := c.save(); err != nil {
		return err
	}

	return nil
}
