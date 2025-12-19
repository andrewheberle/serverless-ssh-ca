package cli

import (
	"context"
	"errors"
	"fmt"
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

// loadconfig will load both system and user configuration
func loadconfig(this *simplecobra.Commandeer) (*config.Config, error) {
	// get root command for config locations
	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return nil, fmt.Errorf("problem accessing root command")
	}

	// make sure user config dir exists
	if err := os.MkdirAll(filepath.Dir(root.userConfigFile), 0755); err != nil {
		return nil, err
	}

	// load config (do not error here on not found)
	config, err := config.LoadConfig(root.systemConfigFile, root.userConfigFile)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// loaduserconfig will only attempt to load the user config
func loaduserconfig(this *simplecobra.Commandeer) (*config.Config, error) {
	// get root command for config locations
	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return nil, fmt.Errorf("problem accessing root command")
	}

	// make sure user config dir exists
	if err := os.MkdirAll(filepath.Dir(root.userConfigFile), 0755); err != nil {
		return nil, err
	}

	config, err := config.LoadUserConfigOnly(root.userConfigFile)
	if err != nil {
		return nil, err
	}

	return config, nil
}
