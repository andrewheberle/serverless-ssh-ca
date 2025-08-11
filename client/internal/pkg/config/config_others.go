//go:build !windows

package config

import (
	"fmt"
	"os"

	"sigs.k8s.io/yaml"
)

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
