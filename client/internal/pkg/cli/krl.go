package cli

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"codeberg.org/sdassow/atomic"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/api"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/krl"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type krlCommand struct {
	host  bool
	out   string
	force bool

	config          *config.SystemConfig
	krlUrl          string
	logger          *slog.Logger
	certificatetype api.GetRevocationListEndpointParamsCertificateType

	*simplecommand.Command
}

func (c *krlCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.host, "host", false, "Retrieve host KRL instead of user KRL")
	cmd.Flags().StringVarP(&c.out, "out", "f", "", "Output file for KRL")
	cmd.Flags().BoolVar(&c.force, "force", false, "Force writing to output even if signature was not verified")

	return nil
}

func (c *krlCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// set up logger
	logger, err := logger(this)
	if err != nil {
		return fmt.Errorf("could not set up logger: %w", err)
	}
	c.logger = logger

	c.logger.Debug("attempting load config", "command", this.CobraCommand.Name())

	// load config
	config, err := loadsystemconfig(this)
	if err != nil {
		return err
	}
	c.config = config

	if c.host {
		c.certificatetype = api.GetRevocationListEndpointParamsCertificateTypeHost
	} else {
		c.certificatetype = api.GetRevocationListEndpointParamsCertificateTypeUser
	}

	return nil
}

func (c *krlCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// get KRL payload from CA
	res, err := krl.Get(c.config.CertificateAuthorityURL, c.certificatetype)
	if err != nil {
		return fmt.Errorf("could not retrieve krl: %w", err)
	}

	if pub := c.config.CertificateAuthority(); pub != nil {
		if err := res.VerifyStrict(pub); err != nil {
			c.logger.Error("verification of krl failed", "error", err)
			return err
		}
	} else {
		c.logger.Warn("trusted_ca not set so signature and CA of krl will not be verified")
		if err := res.Verify(nil); err != nil {
			c.logger.Error("verification of krl failed", "error", err)
			return err
		}

		if !c.force && c.out != "" {
			c.logger.Info("skipping writing krl to output location without force option set", "out", c.out)

			return nil
		}
	}

	if c.out != "" {
		c.logger.Info("writing krl to output file", "out", c.out)
		return atomic.WriteFile(c.out, bytes.NewReader([]byte(res.Krl)), atomic.FileMode(0440))
	}

	return nil
}
