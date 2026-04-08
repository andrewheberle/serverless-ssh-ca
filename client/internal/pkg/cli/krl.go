package cli

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"

	"codeberg.org/sdassow/atomic"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/krl"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type krlCommand struct {
	host  bool
	out   string
	force bool

	config *config.SystemConfig
	krlUrl string
	logger *slog.Logger
	client krlHttpClient

	*simplecommand.Command
}

type krlHttpClient interface {
	Get(url string) (*http.Response, error)
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

	// get URL
	krlUrl, err := c.getKrlUrl()
	if err != nil {
		return fmt.Errorf("could not generate KRL URL: %w", err)
	}
	c.krlUrl = krlUrl

	return nil
}

func (c *krlCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// get KRL payload from CA
	payload, err := c.getKrlPayload()
	if err != nil {
		return fmt.Errorf("could not get krl: %w", err)
	}

	if pub := c.config.CertificateAuthority(); pub != nil {
		if err := payload.VerifyStrict(pub); err != nil {
			c.logger.Error("verification of krl failed", "error", err)
			return err
		}
	} else {
		c.logger.Warn("trusted_ca not set so signature and CA of krl will not be verified")
		if err := payload.Verify(nil); err != nil {
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
		return atomic.WriteFile(c.out, bytes.NewReader([]byte(payload.Krl)), atomic.FileMode(0440))
	}

	return nil
}

func (c *krlCommand) getKrlUrl() (string, error) {
	if c.host {
		return url.JoinPath(c.config.CertificateAuthorityURL, "/api/v3/host/krl")
	}

	return url.JoinPath(c.config.CertificateAuthorityURL, "/api/v3/user/krl")
}

func (c *krlCommand) getKrlPayload() (*krl.Response, error) {
	if c.client == nil {
		c.client = http.DefaultClient
	}

	res, err := c.client.Get(c.krlUrl)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			c.logger.Warn("there was a problem closing the response body", "error", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code for KRL: %d", res.StatusCode)
	}

	return krl.Read(res.Body)
}
