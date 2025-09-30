package config

import (
	"errors"
	"os"
	"path/filepath"
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
