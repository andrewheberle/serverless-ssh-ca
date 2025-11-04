//go:build !windows

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"
)

const AppName = "serverless-ssh-ca"

func ConfigDirs() (user, system string, err error) {
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
	if err := yaml.Unmarshal(y, &config); err != nil {
		return SystemConfig{}, fmt.Errorf("problem parsing system config: %w", err)
	}

	return config, nil
}
