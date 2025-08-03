//go:build tray

package cmd

import (
	"context"
	"embed"
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
	configFile string

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
	cmd.Flags().StringVar(&c.logFile, "log", filepath.Join(home, ConfigDirName, "tray.log"), "Path to log file")
	cmd.Flags().StringVar(&c.configFile, "config", filepath.Join(home, ConfigDirName, "config.yml"), "Path to configuration file")

	return nil
}

func (c *trayCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	c.Command.PreRun(this, runner)

	// set up login client
	lh, err := client.NewLoginHandler(c.configFile, client.WithLifetime(c.lifetime))
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
		// otherwise no logging
		c.logger = slog.New(slog.DiscardHandler)
	}

	return nil
}

func (c *trayCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// make sure to close log file
	defer c.log.Close()

	c.app.RunLogged(c.logger)

	return nil
}

func Execute(ctx context.Context, args []string) error {
	rootCmd := &trayCommand{
		Command: simplecommand.New("ssh-ca-client", "A GUI based client for a serverless SSH CA"),
	}

	// Set up simplecobra
	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	// run command with the provided args
	if _, err := x.Execute(context.Background(), args); err != nil {
		return err
	}

	return nil
}
