package cli

import (
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type hostCommand struct {
	keyTypes []string

	*simplecommand.Command
}

func (c *hostCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.PersistentFlags().StringSliceVar(&c.keyTypes, "keys", []string{"dsa", "ecdsa", "ed25519", "rsa"}, "List of host key types/algorithms to handle")

	return nil
}
