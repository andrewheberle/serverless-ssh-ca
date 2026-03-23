//go:build !windows

package cli

import (
	"fmt"

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
