//go:build !windows

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/host"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type hostCommand struct {
	keypath    []string
	renew      bool
	lifetime   time.Duration
	listenAddr string
	debug      bool
	force      bool
	principals []string

	client *host.LoginHandler

	logger *slog.Logger

	*simplecommand.Command
}

func (c *hostCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	// add hostname to list by default
	principals := make([]string, 0)
	hostname, err := os.Hostname()
	if err == nil {
		principals = append(principals, hostname)
	}

	cmd := cd.CobraCommand
	cmd.Flags().DurationVar(&c.lifetime, "life", host.DefaultLifetime, "Lifetime of SSH certificate")
	cmd.Flags().StringSliceVar(&c.keypath, "key", []string{}, "Path to private key(s)")
	cmd.Flags().StringVar(&c.listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")
	cmd.Flags().StringSliceVar(&c.principals, "principals", principals, "Principals to add to the host certificate request")
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
		c.logger.Warn("not running as root", "uid", os.Geteuid())
	}

	config, err := loadsystemconfig(this)
	if err != nil {
		return err
	}

	// set options
	opts := []host.LoginHandlerOption{
		host.WithLifetime(c.lifetime),
		host.WithPrincipals(c.principals),
		host.WithLogger(c.logger),
	}

	if c.renew {
		opts = append(opts, host.WithRenewal())
	}

	if c.debug {
		logLevel.Set(slog.LevelDebug)
	}

	lh, err := host.NewHostLoginHandler(c.keypath, config, opts...)
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

// loadsystemconfig will only attempt to load the system config file
func loadsystemconfig(this *simplecobra.Commandeer) (*config.SystemConfig, error) {
	// get root command for config locations
	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return nil, fmt.Errorf("problem accessing root command")
	}

	c, err := config.LoadConfig(root.systemConfigFile, "")
	if err != nil {
		return nil, err
	}

	return &config.SystemConfig{
		Issuer:                  c.Oidc().Issuer,
		ClientID:                c.Oidc().ClientID,
		Scopes:                  c.Oidc().Scopes,
		RedirectURL:             c.Oidc().RedirectURL,
		CertificateAuthorityURL: c.CertificateAuthorityURL(),
	}, nil
}
