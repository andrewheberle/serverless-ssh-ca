package cli

import (
	"context"

	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type revokeCommand struct {
	host bool

	*simplecommand.Command
}

func (c *revokeCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	return ErrCommandNotImplemented
}
