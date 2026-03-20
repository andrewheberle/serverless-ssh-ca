package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/bep/simplecobra"
)

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
