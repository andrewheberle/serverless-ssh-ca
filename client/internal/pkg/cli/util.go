package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/bep/simplecobra"
)

// loadconfig will load both system and user configuration
func loadconfig(this *simplecobra.Commandeer) (*config.Config, error) {
	// get system config location
	systemConfigFile, err := this.CobraCommand.Flags().GetString("config")
	if err != nil {
		return nil, fmt.Errorf("problem accessing config flag: %w", err)
	}

	// get user config location
	userConfigFile, err := this.CobraCommand.Flags().GetString("user")
	if err != nil {
		return nil, fmt.Errorf("problem accessing user flag: %w", err)
	}

	// make sure user config dir exists
	if err := os.MkdirAll(filepath.Dir(userConfigFile), 0755); err != nil {
		return nil, err
	}

	// load config (do not error here on not found)
	config, err := config.LoadConfig(systemConfigFile, userConfigFile)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// loaduserconfig will only attempt to load the user config
func loaduserconfig(this *simplecobra.Commandeer) (*config.Config, error) {
	// get user config location
	userConfigFile, err := this.CobraCommand.Flags().GetString("user")
	if err != nil {
		return nil, fmt.Errorf("problem accessing user flag: %w", err)
	}

	// make sure user config dir exists
	if err := os.MkdirAll(filepath.Dir(userConfigFile), 0755); err != nil {
		return nil, err
	}

	config, err := config.LoadUserConfigOnly(userConfigFile)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// loadsystemconfig will only attempt to load the system config file
func loadsystemconfig(this *simplecobra.Commandeer) (*config.SystemConfig, error) {
	// get root command for config locations
	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return nil, fmt.Errorf("problem accessing root command")
	}

	// load config
	c, err := config.LoadConfig(root.systemConfigFile, "")
	if err != nil {
		return nil, err
	}

	// return system portion of config
	return c.System(), nil
}

func logger(this *simplecobra.Commandeer) (*slog.Logger, error) {
	debug, err := this.CobraCommand.Flags().GetBool("debug")
	if err != nil {
		return nil, fmt.Errorf("problem accessing debug flag: %w", err)
	}

	logLevel := new(slog.LevelVar)
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	logger := slog.New(h)

	if debug {
		logLevel.Set(slog.LevelDebug)
	}

	return logger, nil
}
