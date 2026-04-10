//go:build !snap

package cli

import (
	"github.com/bep/simplecobra"
)

func (c *revokeCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.host, "host", false, "Revoke a host certificate instead of a user certificate")

	return nil
}
