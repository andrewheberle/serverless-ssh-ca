//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"sigs.k8s.io/yaml"
)

const AppName = "serverless-ssh-ca"

const (
	keySecretName   = AppName
	tokenSecretName = AppName
)

func ConfigDirs() (user, system string, err error) {
	// are we running as a snap?
	if os.Getenv("SNAP_USER_DATA") != "" && os.Getenv("SNAP_DATA") != "" && os.Getenv("IGNORE_SNAP_DURING_TEST") == "" {
		return os.Getenv("SNAP_USER_DATA"), os.Getenv("SNAP_DATA"), nil
	}

	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}

	return filepath.Join(dir, AppName), filepath.Join("/etc", AppName), nil
}

func loadSystemConfig(name string) (SystemConfig, error) {
	y, err := os.ReadFile(name)
	if err != nil {
		return SystemConfig{}, err
	}

	var config SystemConfig
	if err := yaml.UnmarshalStrict(y, &config); err != nil {
		return SystemConfig{}, fmt.Errorf("problem parsing system config: %w", err)
	}

	if config.TrustedCertificateAuthority != "" {
		ca, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.TrustedCertificateAuthority))
		if err != nil {
			return SystemConfig{}, fmt.Errorf("problem parsing trusted_ca: %w", err)
		}

		config.ca = ca
	}

	return config, nil
}
