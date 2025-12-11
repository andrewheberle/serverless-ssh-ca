//go:build !windows

package cli

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/host"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type hostCommand struct {
	keypath    string
	renew      bool
	lifetime   time.Duration
	listenAddr string
	debug      bool
	force      bool

	client *host.LoginHandler

	logger *slog.Logger

	*simplecommand.Command
}

func (c *hostCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().DurationVar(&c.lifetime, "life", host.DefaultLifetime, "Lifetime of SSH certificate")
	cmd.Flags().StringVar(&c.keypath, "key", "", "Path to private key")
	cmd.Flags().StringVar(&c.listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")
	cmd.Flags().BoolVar(&c.renew, "renew", false, "Renew existing certificate")
	cmd.Flags().BoolVar(&c.debug, "debug", false, "Enable debug logging")
	cmd.Flags().BoolVar(&c.force, "force", false, "Force renewal even if current certificate has more than 50% validity left")

	return nil
}

func (c *hostCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	logLevel := new(slog.LevelVar)
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	c.logger = slog.New(h)

	if os.Geteuid() != 0 {
		c.logger.Warn("this command should be run as root", "uid", os.Geteuid())
	}

	sys, err := loadsystemconfig(this)
	if err != nil {
		return err
	}

	// set options
	opts := []host.LoginHandlerOption{
		host.WithLifetime(c.lifetime),
	}

	opts = append(opts, host.WithLogger(c.logger))

	if c.debug {
		logLevel.Set(slog.LevelDebug)
	}

	lh, err := host.NewHostLoginHandler(c.keypath, &config.SystemConfig{
		Issuer:                  sys.Oidc().Issuer,
		ClientID:                sys.Oidc().ClientID,
		Scopes:                  sys.Oidc().Scopes,
		RedirectURL:             sys.Oidc().RedirectURL,
		CertificateAuthorityURL: sys.CertificateAuthorityURL(),
	}, opts...)
	if err != nil {
		return err
	}

	c.client = lh

	return nil
}

func (c *hostCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// start interactive login
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	return c.client.ExecuteLoginWithContext(ctx, c.listenAddr)
}
