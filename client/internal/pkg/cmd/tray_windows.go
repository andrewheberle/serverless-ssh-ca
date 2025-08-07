//go:build tray

package cmd

import (
	"context"
	"embed"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/allan-simon/go-singleinstance"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/tray"
	"github.com/gen2brain/beeep"
	"github.com/spf13/pflag"
)

//go:embed icons
var resources embed.FS

func Execute(ctx context.Context, args []string) error {
	// find home dir
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	var lifetime time.Duration
	var listenAddr, logFile, crashFile, systemConfigFile, userConfigFile string
	var proxy bool

	pflag.DurationVar(&lifetime, "life", time.Hour*24, "Lifetime of SSH certificate")
	pflag.StringVar(&listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")
	pflag.StringVar(&logFile, "log", filepath.Join(home, ConfigDirName, "tray.log"), "Path to log file")
	pflag.StringVar(&crashFile, "crash", filepath.Join(home, ConfigDirName, "crash.log"), "Path to log file for panics/crashes")
	pflag.StringVar(&systemConfigFile, "config", filepath.Join(home, ConfigDirName, "config.yml"), "Path to configuration file")
	pflag.StringVar(&userConfigFile, "user", filepath.Join(home, ConfigDirName, "user.yml"), "Path to user configuration file")
	pflag.BoolVar(&proxy, "proxy", false, "Enably proxying of PuTTY Agent (pageant) requests")
	pflag.Parse()

	// make sure config dir exists
	if err := os.MkdirAll(filepath.Dir(userConfigFile), 0755); err != nil {
		return err
	}

	// set location to write panics
	crash, err := os.Create(crashFile)
	if err != nil {
		return err
	}
	defer crash.Close()
	debug.SetCrashOutput(crash, debug.CrashOptions{})

	// set options
	opts := []client.LoginHandlerOption{
		client.WithLifetime(lifetime),
		client.AllowWithoutKey(),
	}
	if proxy {
		opts = append(opts, client.WithPageantProxy())
	}

	// set up login client
	lh, err := client.NewLoginHandler(systemConfigFile, userConfigFile, opts...)
	if err != nil {
		return err
	}

	// set up tray app
	beeep.AppName = "Serverless SSH CA Client"
	app, err := tray.New(beeep.AppName, listenAddr, resources, lh)
	if err != nil {
		return err
	}

	// set up logger
	var logger *slog.Logger
	if logFile != "" {
		log, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		defer log.Close()

		logger = slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{}))
		slog.Info("logging to log file", "file", logFile)
	} else {
		// otherwise no logging
		logger = slog.New(slog.DiscardHandler)
	}

	// make sure we are only running once
	lockFile, err := singleinstance.CreateLockFile(filepath.Join(home, ConfigDirName, "tray.lock"))
	if err != nil {
		logger.Error("could not take lock", "error", err)
		return err
	}
	defer lockFile.Close()

	// start pageant proxy if requested
	if proxy {
		logger.Info("attempting to start pageant proxy process")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			if err := lh.RunPageantProxy(ctx); err != nil {
				// dont log an error if the error indicates the context was cancelled
				if !errors.Is(err, context.Canceled) {
					logger.Error("error from pageant proxy", "error", err)
				}
			}
		}()
	}

	app.RunLogged(logger)

	return nil
}
