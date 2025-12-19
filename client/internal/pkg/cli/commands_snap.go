//go:build snap

package cli

import (
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

// when building as a snap the "host" sub-command is not included
func commands() []simplecobra.Commander {
	return []simplecobra.Commander{
		&generateCommand{
			Command: simplecommand.New("generate", "Generate a SSH private key"),
		},
		&loginCommand{
			Command: simplecommand.New("login", "Login via OIDC and request a certificate from CA"),
		},
		&showCommand{
			Command: simplecommand.New("show", "Show existing private/public key"),
		},
		&versionCommand{
			Command: simplecommand.New("version", "Show the current version of the ssh-ca-client"),
		},
	}
}
