package cmd

import (
	"os"
	"path/filepath"
)

const appName = "Serverless SSH CA Client"

func configDirs() (user, system string, err error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", "", err
	}

	return filepath.Join(dir, appName), filepath.Join(os.Getenv("ProgramData"), appName), nil
}
