package cmd

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type rootCommand struct {
	configFile string

	config *config.ClientConfig

	*simplecommand.Command
}

var (
	ErrNoPrivateKey = errors.New("no private key found, please run \"ssh-ca-client generate\"")
)

const ConfigDirName = ".serverless-ssh-ca"

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	c.Command.Init(cd)

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.PersistentFlags().StringVar(&c.configFile, "config", filepath.Join(home, ConfigDirName, "config.yml"), "Path to configuration file")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	c.Command.PreRun(this, runner)

	// make sure config dir exists
	if err := os.MkdirAll(filepath.Dir(c.configFile), 0755); err != nil {
		return err
	}

	// load config
	config, err := config.LoadConfig(c.configFile)
	if err != nil {
		return err
	}
	c.config = config

	return nil
}

// Execute function is in cli.go or tray.go depending on build tags
