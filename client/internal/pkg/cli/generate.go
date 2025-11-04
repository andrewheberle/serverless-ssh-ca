package cli

import (
	"context"
	"fmt"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/sshkey"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type generateCommand struct {
	force bool

	config *config.Config

	*simplecommand.Command
}

func (c *generateCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.force, "force", false, "Force replacing and existing key")

	return nil
}

func (c *generateCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return fmt.Errorf("problem accessing root command")
	}
	c.config = root.config
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
