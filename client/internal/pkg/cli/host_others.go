//go:build !windows

package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

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
	force      bool
	principals []string
	renewat    float64

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
	cmd.Flags().BoolVar(&c.force, "force", false, fmt.Sprintf("Force renewal even if current certificate has more than %0.1f%% validity left", host.DefaultRenewAt*100.0))
	cmd.Flags().Float64Var(&c.renewat, "renewat", host.DefaultRenewAt, "Renew at fraction of lifetime")
	cmd.MarkFlagsMutuallyExclusive("force", "renewat")

	return nil
}

func (c *hostCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// set up logger
	logger, err := logger(this)
	if err != nil {
		return fmt.Errorf("could not set up logger: %w", err)
	}
	c.logger = logger

	if c.renewat < 0 || c.renewat > 1 {
		return fmt.Errorf("renewat must be between 0 and 1")
	}

	if os.Geteuid() != 0 {
		c.logger.Warn("not running as root", "uid", os.Geteuid())
	}

	c.logger.Debug("attempting load config", "command", this.CobraCommand.Name())

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

	lh, err := host.NewHostLoginHandler(c.keypath, config, opts...)
	if err != nil {
		return err
	}

	c.client = lh

	return nil
}

func (c *hostCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// start interactive login
	return c.client.ExecuteLogin(c.listenAddr)
}
