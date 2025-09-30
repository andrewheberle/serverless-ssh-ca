package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type rootCommand struct {
	systemConfigFile string
	userConfigFile   string

	*simplecommand.Command
}

var (
	ErrNoPrivateKey   = errors.New("no private key found, please run \"ssh-ca-client generate\"")
	ErrNotImplemented = errors.New("not implemented")
)

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	user, system, err := config.ConfigDirs()
	if err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.PersistentFlags().StringVar(&c.systemConfigFile, "config", filepath.Join(system, "config.yml"), "Path to configuration file")
	cmd.PersistentFlags().StringVar(&c.userConfigFile, "user", filepath.Join(user, "user.yml"), "Path to user configuration file")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// make sure user config dir exists
	if err := os.MkdirAll(filepath.Dir(c.userConfigFile), 0755); err != nil {
		return err
	}

	return nil
}

func Execute(ctx context.Context, args []string) error {
	rootCmd := &rootCommand{
		Command: simplecommand.New("ssh-ca-client-cli", "A CLI based client for a serverless SSH CA"),
	}

	// set up host subcommand structure
	hostCmd := simplecommand.New("host", "Handle host keys")

	rootCmd.SubCommands = []simplecobra.Commander{
		&generateCommand{
			Command: simplecommand.New("generate", "Generate a SSH private key"),
		},
		&loginCommand{
			Command: simplecommand.New("login", "Login via OIDC and request a certificate from CA"),
		},
		&showCommand{
			Command: simplecommand.New("show", "Show existing private/public key"),
		},
		&versionCommand{
			Command: simplecommand.New("version", "Show the current version of the ssh-ca-client"),
		},
		hostCmd,
	}

	// Set up simplecobra
	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	// run command with the provided args
	if _, err := x.Execute(ctx, args); err != nil {
		return err
	}

	return nil
}
