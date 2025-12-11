package gui

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/allan-simon/go-singleinstance"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/tray"
	"github.com/spf13/pflag"
)

//go:embed icons
var resources embed.FS

func Execute(ctx context.Context, args []string) error {
	// beeep.AppName = config.FriendlyAppName

	// find config dirs
	user, system, err := config.ConfigDirs()
	if err != nil {
		return err
	}

	var lifetime, renewAt time.Duration
	var listenAddr, logDir, systemConfigFile, userConfigFile string
	var install, uninstall, disableProxy, addOnStart bool

	flags := pflag.NewFlagSet("tray", pflag.ExitOnError)

	flags.DurationVar(&lifetime, "life", time.Hour*24, "Lifetime of SSH certificate")
	flags.DurationVar(&renewAt, "renew", time.Hour, "Renew once remaining time gets below this value")
	flags.StringVar(&listenAddr, "addr", "localhost:3000", "Listen address for OIDC auth flow")
	flags.StringVar(&logDir, "log", filepath.Join(user, "log"), "Log directory")
	flags.StringVar(&systemConfigFile, "config", filepath.Join(system, "config.yml"), "Path to configuration file")
	flags.StringVar(&userConfigFile, "user", filepath.Join(user, "user.yml"), "Path to user configuration file")
	// only proxy pageant on Windows
	if runtime.GOOS == "windows" {
		flags.BoolVar(&disableProxy, "disable-proxy", false, "Disable proxying of PuTTY Agent (pageant) requests")
	} else {
		// always disabled on non-Windows platforms
		disableProxy = true
	}
	flags.BoolVar(&addOnStart, "add-on-start", true, "Add current key and certificate (if valid) to SSH agent on start")
	flags.BoolVar(&install, "install", false, "Perform post-install steps")
	_ = flags.MarkHidden("install")
	flags.BoolVar(&uninstall, "uninstall", false, "Perform pre-uninstall steps")
	_ = flags.MarkHidden("uninstall")
	_ = flags.Parse(args)

	// ensure install and uninstall are not called togther
	if install && uninstall {
		return fmt.Errorf("--install and --uninstall cannot be used together")
	}

	// handle install or uninstall
	if install {
		return runInstall()
	}
	if uninstall {
		return runUninstall()
	}

	// check renewAt is not larger than lifetime
	if renewAt > lifetime {
		return fmt.Errorf("--renew cannot be larger than --life")
	}

	// make sure user config dir exists
	if err := os.MkdirAll(user, 0755); err != nil {
		return err
	}

	// make sure log dir exists
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	// load config
	c, err := config.LoadConfig(systemConfigFile, userConfigFile)
	if err != nil {
		return err
	}

	// set location to write panics
	crashFile := filepath.Join(logDir, "crash.log")
	crash, err := os.Create(crashFile)
	if err != nil {
		return err
	}
	defer func() {
		_ = crash.Close()
	}()
	_ = debug.SetCrashOutput(crash, debug.CrashOptions{})

	// set options
	opts := []client.LoginHandlerOption{
		client.WithLifetime(lifetime),
		client.AllowWithoutKey(),
	}
	if !disableProxy {
		opts = append(opts, client.WithPageantProxy())
	}

	// set up login client
	lh, err := client.NewLoginHandler(c, opts...)
	if err != nil {
		return err
	}

	// set up tray app
	app, err := tray.New(config.FriendlyAppName, listenAddr, resources, lh, renewAt)
	if err != nil {
		return err
	}

	// set up logger
	logFile := filepath.Join(logDir, "tray.log")
	log, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		_ = log.Close()
	}()

	logger := slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{}))
	logger.Info("logging to log file", "file", logFile)

	// make sure we are only running once
	lockFile, err := singleinstance.CreateLockFile(filepath.Join(user, "tray.lock"))
	if err != nil {
		logger.Error("could not take lock", "error", err)
		return err
	}
	defer func() {
		_ = lockFile.Close()
	}()

	// start pageant proxy if requested
	if !disableProxy {
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

	// try to add to agent on start
	if addOnStart {
		logger.Info("attempting to add current certificate to ssh agent")
		if err := lh.AddToAgent(); err != nil {
			logger.Warn("could not add current certificate to ssh agent", "error", err)
		}
	}

	app.RunLogged(logger)

	return nil
}
