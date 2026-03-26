package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"github.com/forfuncsake/krl"
	"github.com/hiddeco/sshsig"
)

type krlCommand struct {
	host  bool
	out   string
	force bool

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
	res, err := http.Get(c.krlUrl)
	if err != nil {
		return err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			c.logger.Warn("there was a problem closing the response body", "error", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code for KRL: %d", res.StatusCode)
	}

	var payload krlResponsePayload
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		return err
	}

	// parse krl
	c.logger.Debug("parsing krl to ensure its valid")
	if _, err := krl.ParseKRL(payload.KeyRevocationList); err != nil {
		return fmt.Errorf("problem parsing krl: %w", err)
	}

	if c.config.TrustedCertificateAuthority != "" {
		sig, err := sshsig.Unarmor([]byte(payload.Signature))
		if err != nil {
			return fmt.Errorf("problem unarmoring signature: %w", err)
		}

		if err := sshsig.Verify(bytes.NewReader(payload.KeyRevocationList), sig, c.config.CertificateAuthority(), sig.HashAlgorithm, "file"); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}

		c.logger.Info("signature verified ok")
	} else {
		c.logger.Warn("trusted_ca not set so signature will not be verified")

		if !c.force && c.out != "" {
			c.logger.Info("skipping writing krl to output location without force option set", "out", c.out)

			return nil
		}
	}

	if c.out != "" {
		c.logger.Info("writing krl to output file", "out", c.out)
		return os.WriteFile(c.out, payload.KeyRevocationList, 0644)
	}

	return nil
}

func (c *krlCommand) getKrlUrl() (string, error) {
	if c.host {
		return url.JoinPath(c.config.CertificateAuthorityURL, "/api/v3/host/krl")
	}

	return url.JoinPath(c.config.CertificateAuthorityURL, "/api/v3/user/krl")
}

type krlResponsePayload struct {
	KeyRevocationList []byte `json:"krl"`
	Signature         string `json:"signature"`
}
