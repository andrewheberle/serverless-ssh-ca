package cli

import (
	"context"
	"fmt"
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
	debug      bool

	client *client.LoginHandler

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
	cmd.Flags().BoolVar(&c.debug, "debug", false, "Enable debug logging")

	return nil
}

func (c *loginCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return fmt.Errorf("problem accessing root command")
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
	logger := slog.New(h)

	opts = append(opts, client.WithLogger(logger))

	if c.debug {
		logLevel.Set(slog.LevelDebug)
	}

	// set up login client
	lh, err := client.NewLoginHandler(root.systemConfigFile, root.userConfigFile, opts...)
	if err != nil {
		return err
	}
	c.client = lh

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
