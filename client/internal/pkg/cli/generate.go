package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	hostconfig "github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config/host"
	userconfig "github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config/user"
	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/sshkey"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type generateCommand struct {
	force bool

	// handle host keys
	host bool

	config config.Config

	*simplecommand.Command
}

func (c *generateCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.force, "force", false, "Force replacing any existing key(s)")

	return nil
}

func (c *generateCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// get root command flags
	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return fmt.Errorf("problem accessing root command")
	}

	// load config
	if c.host {
		config, err := hostconfig.LoadConfig(root.systemConfigFile)
		if err != nil {
			return err
		}

		c.config = config
	} else {
		config, err := userconfig.LoadConfig(root.systemConfigFile, root.userConfigFile)
		if err != nil {
			return err
		}

		c.config = config
	}

	return nil
}

func (c *generateCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	if c.config.HasPrivateKey() && !c.force {
		return fmt.Errorf("not overwriting existing private key without force option set")
	}

	// set comment based on user@host if possible
	user := "nobody"
	host := "nowhere"
	if u := os.Getenv("USERNAME"); u != "" {
		user = u
	} else if u := os.Getenv("USER"); u != "" {
		user = u
	}
	if h := os.Getenv("COMPUTERNAME"); h != "" {
		host = h
	}

	pemBytes, err := sshkey.GenerateKey(user + "@" + host)
	if err != nil {
		return err
	}

	if err := c.config.SetPrivateKeyBytes(pemBytes); err != nil {
		return err
	}

	return nil
}
