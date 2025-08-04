//go:build !tray

package cmd

import (
	"context"

	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

func Execute(ctx context.Context, args []string) error {
	rootCmd := &rootCommand{
		Command: simplecommand.New("ssh-ca-client-cli", "A CLI based client for a serverless SSH CA"),
	}
	rootCmd.SubCommands = []simplecobra.Commander{
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

	// Set up simplecobra
	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	// run command with the provided args
	if _, err := x.Execute(ctx, args); err != nil {
		return err
	}

	return nil
}
