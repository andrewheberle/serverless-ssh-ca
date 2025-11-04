package config

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
	"sigs.k8s.io/yaml"
)

var (
	ErrConfigIncomplete = errors.New("config was incomplete")
)

const AppName = "Serverless SSH CA Client"

func ConfigDirs() (user, system string, err error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}

	return filepath.Join(dir, AppName), filepath.Join(os.Getenv("ProgramData"), AppName), nil
}

func loadPolicy() SystemConfig {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, "Software\\Policies\\Serverless SSH CA Client", registry.QUERY_VALUE)
	if err != nil {
		return SystemConfig{}
	}
	defer func() {
		_ = k.Close()
	}()

	var config SystemConfig
	clientId, _, err := k.GetStringValue("ClientID")
	if err == nil {
		config.ClientID = clientId
	}

	issuer, _, err := k.GetStringValue("Issuer")
	if err == nil {
		config.Issuer = issuer
	}

	scopes, _, err := k.GetStringsValue("Scopes")
	if err == nil {
		config.Scopes = scopes
	}

	redirectURL, _, err := k.GetStringValue("RedirectURL")
	if err == nil {
		config.RedirectURL = redirectURL
	}

	certificateAuthorityURL, _, err := k.GetStringValue("CertificateAuthorityURL")
	if err == nil {
		config.CertificateAuthorityURL = certificateAuthorityURL
	}

	return config
}

func loadConfig(name string) SystemConfig {
	y, err := os.ReadFile(name)
	if err != nil {
		return SystemConfig{}
	}

	var config SystemConfig
	if err := yaml.Unmarshal(y, &config); err != nil {
		return SystemConfig{}
	}

	return config
}

// Function merges a -> b with values set in a overridding b
//
// An error is returned if values are not set after merge
func mergeConfig(a, b SystemConfig) (SystemConfig, error) {
	if a.ClientID != "" {
		b.ClientID = a.ClientID
	}

	if a.Issuer != "" {
		b.Issuer = a.Issuer
	}

	if len(a.Scopes) > 0 {
		b.Scopes = a.Scopes
	}

	if a.RedirectURL != "" {
		b.RedirectURL = a.RedirectURL
	}

	if a.CertificateAuthorityURL != "" {
		b.CertificateAuthorityURL = a.CertificateAuthorityURL
	}

	if a.ClientID == "" || a.Issuer == "" || len(a.Scopes) == 0 || a.RedirectURL == "" || a.CertificateAuthorityURL == "" {
		return SystemConfig{}, ErrConfigIncomplete
	}

	return b, nil
}

func loadSystemConfig(name string) (SystemConfig, error) {
	local := loadConfig(name)
	policy := loadPolicy()

	return mergeConfig(policy, local)
}
