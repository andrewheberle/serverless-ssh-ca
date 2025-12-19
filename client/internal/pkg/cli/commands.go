//go:build !snap

package cli

import (
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

// with no build tags all sub-commands are included
func commands() []simplecobra.Commander {
	return []simplecobra.Commander{
		&generateCommand{
			Command: simplecommand.New("generate", "Generate a SSH private key"),
		},
		&hostCommand{
			Command: simplecommand.New("host", "Request or renew host certificates"),
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
