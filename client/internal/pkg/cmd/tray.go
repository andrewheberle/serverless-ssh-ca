package cmd

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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
	logFile    string

	app    *tray.Application
	logger *slog.Logger
	log    *os.File

	*simplecommand.Command
}

func (c *trayCommand) Init(cd *simplecobra.Commandeer) error {
	c.Command.Init(cd)

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().DurationVar(&c.lifetime, "life", time.Hour*24, "Lifetime of SSH certificate")
	cmd.Flags().StringVar(&c.listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")
	cmd.Flags().StringVar(&c.logFile, "log", filepath.Join(home, configDirName, "tray.log"), "Path to log file")

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

	// set up logger
	if c.logFile != "" {
		f, err := os.OpenFile(c.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		c.log = f
		c.logger = slog.New(slog.NewTextHandler(c.log, &slog.HandlerOptions{}))
		slog.Info("logging to log file", "file", c.logFile)
	} else {
		// otherwise log to stdout
		c.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	}

	return nil
}

func (c *trayCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// make sure to close log file
	defer c.log.Close()

	c.app.RunLogged(c.logger)

	return nil
}
