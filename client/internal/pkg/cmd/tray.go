package cmd

import (
	"context"
	"embed"
	"fmt"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/tray"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"github.com/gen2brain/beeep"
)

//go:embed icons
var resources embed.FS

type trayCommand struct {
	// command line args
	lifetime   time.Duration
	listenAddr string

	app *tray.Application

	*simplecommand.Command
}

func (c *trayCommand) Init(cd *simplecobra.Commandeer) error {
	c.Command.Init(cd)

	cmd := cd.CobraCommand
	cmd.Flags().DurationVar(&c.lifetime, "life", time.Hour*24, "Lifetime of SSH certificate")
	cmd.Flags().StringVar(&c.listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")

	return nil
}

func (c *trayCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	c.Command.PreRun(this, runner)

	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return fmt.Errorf("problem accessing root command")
	}

	// set up login client
	lh, err := client.NewLoginHandler(root.configFile, client.WithLifetime(c.lifetime))
	if err != nil {
		return err
	}

	// set up tray app
	beeep.AppName = "Serverless SSH CA Client"
	app, err := tray.New(beeep.AppName, c.listenAddr, resources, lh)
	if err != nil {
		return err
	}
	c.app = app

	return nil
}

func (c *trayCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	c.app.Run()

	return nil
}
