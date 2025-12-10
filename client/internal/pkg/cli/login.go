package cli

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type loginCommand struct {
	skipAgent  bool
	lifetime   time.Duration
	showTokens bool
	listenAddr string
	add        bool
	debug      bool
	force      bool

	client *client.LoginHandler

	logger *slog.Logger

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
	cmd.Flags().BoolVar(&c.skipAgent, "skip-agent", false, "Skip adding SSH key and certificate to ssh-agent")
	cmd.Flags().BoolVar(&c.showTokens, "show-tokens", false, "Display OIDC tokens after login process")
	cmd.Flags().DurationVar(&c.lifetime, "life", time.Hour*24, "Lifetime of SSH certificate")
	cmd.Flags().StringVar(&c.listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")
	cmd.Flags().BoolVar(&c.add, "add", false, "Add existing certificate to SSH agent")
	cmd.Flags().BoolVar(&c.debug, "debug", false, "Enable debug logging")
	cmd.Flags().BoolVar(&c.force, "force", false, "Force renewal even if current certificate has more than 50% validity left")

	return nil
}

func (c *loginCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	// load config
	config, err := loadconfig(this)
	if err != nil {
		return err
	}

	// set options
	opts := []client.LoginHandlerOption{
		client.WithLifetime(c.lifetime),
	}
	if c.showTokens {
		opts = append(opts, client.ShowTokens())
	}
	if c.skipAgent {
		opts = append(opts, client.SkipAgent())
	}

	logLevel := new(slog.LevelVar)
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	c.logger = slog.New(h)

	opts = append(opts, client.WithLogger(c.logger))

	if c.debug {
		logLevel.Set(slog.LevelDebug)
	}

	// set up login client
	lh, err := client.NewLoginHandler(config, opts...)
	if err != nil {
		return err
	}
	c.client = lh

	return nil
}

func (c *loginCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// just add if requested
	if c.add {
		c.logger.Info("attempting to add current certificate to ssh-agent")
		return c.client.AddToAgent()
	}

	// check life is not more than 50% done
	if time.Now().Add(c.lifetime / 2).Before(c.client.CerificateExpiry()) {
		if !c.force {
			c.logger.Info("skipping renewal as current certificate has more than 50% of its lifetime left")

			return nil

		} else {
			c.logger.Info("renewal forced despite current certificate having more than 50% of its lifetime lef")
		}
	}

	// try refresh first
	if err := c.client.Refresh(); err == nil {
		return nil
	} else {
		c.logger.Warn("error during refresh", "error", err)
		if errors.Is(err, client.ErrAddingToAgent) || errors.Is(err, client.ErrConnectingToAgent) {
			c.logger.Info("skipping interactive login flow as error was related to SSH agent")
		}

	}

	// otherwise do interactive login
	ctx, cancel := context.WithTimeout(ctx, time.Second*30)
	defer cancel()

	return c.client.ExecuteLoginWithContext(ctx, c.listenAddr)
}
