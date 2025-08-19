//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
)

const appName = "serverless-ssh-ca"

func configDirs() (user, system string, err error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}

	return filepath.Join(dir, appName), filepath.Join("/etc", appName), nil
}
