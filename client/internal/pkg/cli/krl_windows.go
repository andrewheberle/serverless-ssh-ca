package cli

import (
	"context"
	"fmt"
	"runtime"

	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type krlCommand struct {
	*simplecommand.Command
}

func (c *krlCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	return fmt.Errorf("this command is not supported on %s", runtime.GOOS)
}
