package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	deviceclient "github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client/device"
	userclient "github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client/user"
	hostconfig "github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config/host"
	userconfig "github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config/user"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type loginCommand struct {
	skipAgent  bool
	lifetime   time.Duration
	showTokens bool
	listenAddr string

	// handle host keys
	host bool

	client client.LoginHandler

	*simplecommand.Command
}

type CertificateSignerResponse struct {
	Certificate []byte `json:"certificate"`
}

func (c *loginCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand

	// adjust flags based on host keys or not
	if c.host {
		c.skipAgent = true
		cmd.Flags().DurationVar(&c.lifetime, "life", time.Hour*24*90, "Lifetime of host SSH certificate")
	} else {
		cmd.Flags().BoolVar(&c.skipAgent, "skip-agent", false, "Skip adding SSH key and certificate to ssh-agent")
		cmd.Flags().BoolVar(&c.showTokens, "show-tokens", false, "Display OIDC tokens after login process")
		cmd.Flags().DurationVar(&c.lifetime, "life", time.Hour*24, "Lifetime of SSH certificate")
		cmd.Flags().StringVar(&c.listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")
	}

	return nil
}

func (c *loginCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// get root command flags
	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return fmt.Errorf("problem accessing root command")
	}

	// handle host key config
	if c.host {
		return ErrNotImplemented
	}

	// load config
	if c.host {
		config, err := hostconfig.LoadConfig(root.systemConfigFile)
		if err != nil {
			return err
		}

		// set up login client for device code flow
		lh, err := deviceclient.NewLoginHandler(config, deviceclient.WithLifetime(c.lifetime))
		if err != nil {
			return err
		}
		c.client = lh
	} else {
		config, err := userconfig.LoadConfig(root.systemConfigFile, root.userConfigFile)
		if err != nil {
			return err
		}

		// set options
		opts := []userclient.UserLoginHandlerOption{
			userclient.WithLifetime(c.lifetime),
		}
		if c.showTokens {
			opts = append(opts, userclient.ShowTokens())
		}
		if c.skipAgent {
			opts = append(opts, userclient.SkipAgent())
		}

		// set up login client
		lh, err := userclient.NewLoginHandler(config, opts...)
		if err != nil {
			return err
		}
		c.client = lh
	}

	return nil
}

func (c *loginCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// try refresh first
	if err := c.client.Refresh(); err == nil {
		return nil
	}

	// otherwise do interactive login
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	return c.client.ExecuteLoginWithContext(ctx, c.listenAddr)
}
