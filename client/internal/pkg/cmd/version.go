package cmd

import (
	"context"
	"fmt"
	"runtime/debug"

	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type versionCommand struct {
	*simplecommand.Command
}

func (c *versionCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Printf("%s Unknown\n", cd.Root.Command.Name())
	}
	fmt.Printf("%s %s\n", cd.Root.Command.Name(), info.Main.Version)

	return nil
}
