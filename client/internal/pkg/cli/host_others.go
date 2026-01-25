//go:build !windows

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/host"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type hostCommand struct {
	keypath    []string
	renew      bool
	delay      time.Duration
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
		principals = append(principals, strings.ToLower(hostname))
	}

	cmd := cd.CobraCommand
	cmd.Flags().DurationVar(&c.lifetime, "life", host.DefaultLifetime, "Lifetime of SSH certificate")
	cmd.Flags().DurationVar(&c.delay, "delay", host.DefaultDelay, "Delay between requests/renewals")
	cmd.Flags().StringSliceVar(&c.keypath, "key", []string{"/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_rsa_key"}, "Path to private key(s)")
	cmd.Flags().StringVar(&c.listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")
	cmd.Flags().StringSliceVar(&c.principals, "principals", principals, "Principals to add to the host certificate request")
	cmd.Flags().BoolVar(&c.renew, "renew", false, "Renew existing certificate")
	cmd.MarkFlagsMutuallyExclusive("renew", "principals")
	cmd.Flags().BoolVar(&c.debug, "debug", false, "Enable debug logging")
	cmd.Flags().BoolVar(&c.force, "force", false, fmt.Sprintf("Force renewal even if current certificate has more than %0.1f%% validity left", host.DefaultRenewAt*100.0))

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
		host.WithDelay(c.delay),
	}

	if c.renew {
		opts = append(opts, host.WithRenewal())
		if c.force {
			opts = append(opts, host.WithRenewAt(1.0))
		}
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
