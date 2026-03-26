package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type krlCommand struct {
	host bool
	out  string

	config *config.SystemConfig
	krlUrl string
	logger *slog.Logger

	*simplecommand.Command
}

func (c *krlCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.host, "host", false, "Retrieve host KRL instead of user KRL")
	cmd.Flags().StringVarP(&c.out, "out", "f", "-", "Output file for KRL")

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
	res, err := http.Get(c.krlUrl)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code for KRL: %d", res.StatusCode)
	}

	if c.out == "-" {
		if _, err := io.Copy(os.Stdout, res.Body); err != nil {
			return err
		}

		return nil
	}

	c.logger.Warn("this only writes to stdout at this time")

	return nil
}

func (c *krlCommand) getKrlUrl() (string, error) {
	if c.host {
		return url.JoinPath(c.config.CertificateAuthorityURL, "/api/v3/host/krl")
	}

	return url.JoinPath(c.config.CertificateAuthorityURL, "/api/v3/user/krl")
}
