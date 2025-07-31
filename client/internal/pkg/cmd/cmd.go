package cmd

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
	configFile string
	listenPort int

	config *config.ClientConfig

	*simplecommand.Command
}

var (
	ErrNoPrivateKey = errors.New("no private key found, please run \"ssh-ca-client generate\"")
)

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	c.Command.Init(cd)

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.PersistentFlags().StringVar(&c.configFile, "config", filepath.Join(home, ".serverless-ssh-ca", "config.yml"), "Path to configuration file")
	cmd.PersistentFlags().IntVarP(&c.listenPort, "port", "p", 3000, "Listen port for OIDC auth flow")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	c.Command.PreRun(this, runner)

	config, err := config.LoadConfig(c.configFile)
	if err != nil {
		return err
	}
	c.config = config

	return nil
}

func Execute(ctx context.Context, args []string) error {
	rootCmd := &rootCommand{
		Command: simplecommand.New("ssh-ca-client", "A client for a serverless SSH CA"),
	}
	rootCmd.SubCommands = []simplecobra.Commander{
		&loginCommand{
			Command: simplecommand.New("login", "Login via OIDC and request a certificate from CA"),
		},
		&generateCommand{
			Command: simplecommand.New("generate", "Generate a SSH private key"),
		},
		&showCommand{
			Command: simplecommand.New("show", "Show existing private/public key"),
		},
	}

	// Set up simplecobra
	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	// run command with the provided args
	if _, err := x.Execute(context.Background(), args); err != nil {
		return err
	}

	return nil
}
