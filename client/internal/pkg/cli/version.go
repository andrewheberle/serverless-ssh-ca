package cli

import (
	"context"
	"fmt"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/version"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type versionCommand struct {
	*simplecommand.Command
}

func (c *versionCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	fmt.Printf("%s %s\n", cd.Root.Command.Name(), version.Version())

	return nil
}
