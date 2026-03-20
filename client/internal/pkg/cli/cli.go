package cli

import (
	"context"
	"errors"
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
	ErrNoPrivateKey = errors.New("no private key found, please run \"ssh-ca-client generate\"")
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

	return nil
}

func Execute(ctx context.Context, args []string) error {
	rootCmd := &rootCommand{
		Command: simplecommand.New("ssh-ca-client-cli", "A CLI based client for a serverless SSH CA"),
	}
	rootCmd.SubCommands = commands()

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
