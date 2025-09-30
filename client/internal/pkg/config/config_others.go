//go:build !windows

package config

import (
	"os"
	"path/filepath"
)

const AppName = "serverless-ssh-ca"

func ConfigDirs() (user, system string, err error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}

	return filepath.Join(dir, AppName), filepath.Join("/etc", AppName), nil
}
