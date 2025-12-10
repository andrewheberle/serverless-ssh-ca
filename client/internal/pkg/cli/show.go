package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type showCommand struct {
	private     bool
	certificate bool
	status      bool

	config *config.Config

	*simplecommand.Command
}

func (c *showCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.private, "private", false, "Display private key")
	cmd.Flags().BoolVar(&c.certificate, "certificate", false, "Display certificate if one exists")
	cmd.Flags().BoolVar(&c.status, "status", false, "Display status only")
	cmd.MarkFlagsMutuallyExclusive("status", "private")
	cmd.MarkFlagsMutuallyExclusive("status", "certificate")

	return nil
}

func (c *showCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return fmt.Errorf("problem accessing root command")
	}
	if root.config == nil {
		return fmt.Errorf("config not loaded")
	}
	c.config = root.config
	return nil
}

func (c *showCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	if c.status {
		if !c.config.HasPrivateKey() {
			fmt.Printf("Private Key:        missing\n")
			fmt.Printf("Certificate:        N/A\n")
			fmt.Printf("Certificate Status: N/A\n")
			fmt.Printf("Certificate Expiry: N/A\n")

			return nil
		}

		if !c.config.HasCertificate() {
			fmt.Printf("Private Key:        exists\n")
			fmt.Printf("Certificate:        missing\n")
			fmt.Printf("Certificate Status: N/A\n")
			fmt.Printf("Certificate Expiry: N/A\n")

			return nil
		}

		status := "valid"
		if !c.config.CertificateValid() {
			status = "expired"
		}
		expiry := c.config.CerificateExpiry()
		fmt.Printf("Private Key:        exists\n")
		fmt.Printf("Certificate:        exists\n")
		fmt.Printf("Certificate Status: %s\n", status)
		fmt.Printf("Certificate Expiry: %v (%s)\n", expiry, time.Until(expiry))

		return nil
	}

	if !c.config.HasPrivateKey() {
		return ErrNoPrivateKey
	}

	if c.private {
		pemBytes, err := c.config.GetPrivateKeyBytes()
		if err != nil {
			return err
		}

		fmt.Printf("%s", pemBytes)
	}

	pemBytes, err := c.config.GetPublicKeyBytes()
	if err != nil {
		return err
	}

	fmt.Printf("SSH Public Key: %s", pemBytes)

	if c.certificate {
		certBytes, err := c.config.GetCertificateBytes()
		if err == nil {
			fmt.Printf("SSH Certificate: %s", certBytes)
		}
	}

	return nil
}
