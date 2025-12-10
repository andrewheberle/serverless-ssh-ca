//go:build windows || linux

package tray

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"time"

	"fyne.io/systray"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
)

type appState string

const (
	// states
	stateInit               appState = "Init"
	stateKeyMissing         appState = "KeyMissing"
	stateKeyOK              appState = "KeyOK"
	stateCertificateOK      appState = "CertificateOK"
	stateCertificateMissing appState = "CertificateMissing"
	stateCertificateExpired appState = "CertificateExpired"

	defaultIcon = okIcon

	okIcon      = "ok"
	warningIcon = "warning"
	errorIcon   = "error"
)

type Application struct {
	client  *client.LoginHandler
	done    chan bool
	title   string
	addr    string
	renewAt time.Duration

	trayIcons         map[string][]byte
	notificationIcons map[string][]byte
	state             appState

	mExpiry   *systray.MenuItem
	mGenerate *systray.MenuItem
	mRenew    *systray.MenuItem
	mQuit     *systray.MenuItem

	mu             sync.Mutex
	refreshBackOff int
	refreshFailure int

	logger *slog.Logger
}

var (
	ErrRenewSkipped = errors.New("renew skipped")
	ErrRenewRunning = errors.New("a renew was already in progress")
)

func New(title, addr string, fs embed.FS, client *client.LoginHandler, renewAt time.Duration) (*Application, error) {
	app := &Application{
		addr:              addr,
		client:            client,
		done:              make(chan bool),
		logger:            slog.New(slog.DiscardHandler),
		notificationIcons: make(map[string][]byte),
		renewAt:           renewAt,
		state:             stateInit,
		title:             title,
		trayIcons:         make(map[string][]byte),
	}

	// load tray icons
	for name, file := range trayIconFiles() {
		icon, err := fs.ReadFile(file)
		if err != nil {
			return nil, err
		}

		app.trayIcons[name] = icon
	}

	// load notification icons
	nIcons := map[string]string{
		okIcon:      "icons/ok.png",
		errorIcon:   "icons/error.png",
		warningIcon: "icons/warning.png",
	}
	for name, file := range nIcons {
		icon, err := fs.ReadFile(file)
		if err != nil {
			return nil, err
		}

		app.notificationIcons[name] = icon
	}

	return app, nil
}

func (app *Application) Run() {
	app.prerun()
	systray.Run(app.onReady, func() {})
}

func (app *Application) RunLogged(logger *slog.Logger) {
	if logger != nil {
		app.logger = logger
		app.client.SetLogger(logger)
	}
	app.prerun()
	systray.Run(app.onReady, func() {})
}

func (app *Application) onReady() {
	// set title and icon
	systray.SetTitle(app.title)

	// build menu
	app.mRenew = systray.AddMenuItem("Renew", "Renew certificate")
	app.mGenerate = systray.AddMenuItem("Generate", "Generate private key")
	systray.AddSeparator()
	app.mExpiry = systray.AddMenuItem("Unknown", "Current expiry unknown")
	app.mExpiry.Disable()
	systray.AddSeparator()
	app.mQuit = systray.AddMenuItem("Quit", "Close application")

	// set initial state
	app.setState()

	// send some status
	app.logger.Info("tray application started",
		"client_id", app.client.OIDCConfig().ClientID,
		"issuer", app.client.OIDCConfig().Issuer,
		"redirect_url", app.client.OIDCConfig().RedirectURL,
		"scopes", app.client.OIDCConfig().Scopes,
		"ssh_ca_url", app.client.CertificateAuthorityURL(),
	)

	// handle clicks
	go app.eventloop()
}

func (app *Application) setState() {
	switch app.state {
	case stateInit:
		// we are starting up
		app.logger.Info("starting up")
		if app.client.HasPrivateKey() {
			// have a private key
			app.state = stateKeyOK
		} else {
			// no private key
			app.state = stateKeyMissing
		}

		// re-run to handle change
		app.setState()
	case stateKeyMissing:
		app.logger.Info("no private key found")
		app.mGenerate.Enable()
		app.mRenew.Disable()
		app.mExpiry.SetTitle("No certificate")
		setTooltip("No private key found")
		systray.SetIcon(app.trayIcons["error"])
	case stateKeyOK:
		// we have a key so check the state of the certificate
		app.logger.Info("private key found")
		app.mGenerate.Disable()
		if !app.client.HasCertificate() {
			// no certificate
			app.state = stateCertificateMissing
		} else {
			if app.client.CertificateValid() {
				// certificate is valid
				app.state = stateCertificateOK
			} else {
				// expired certficate
				app.state = stateCertificateExpired
			}
		}

		// re-run to handle change
		app.setState()
	case stateCertificateExpired:
		// check we haven't renewed
		if app.client.CertificateValid() {
			app.logger.Info("certificate renewed")
			app.state = stateCertificateOK
			// re-run to handle change
			app.setState()
			// finish now
			break
		}

		app.mRenew.SetTitle("Renew")
		app.mRenew.Enable()
		app.mExpiry.SetTitle("Certificate expired")
		setTooltip("Certificate expired")
		systray.SetIcon(app.trayIcons["warning"])
	case stateCertificateMissing:
		// check we haven't renewed
		if app.client.CertificateValid() {
			app.logger.Info("certificate issued")
			app.state = stateCertificateOK
			// re-run to handle change
			app.setState()
			// finish now
			break
		}
		app.mRenew.SetTitle("Request")
		app.mRenew.Enable()
		app.mExpiry.SetTitle("No certificate")
		setTooltip("No certificate found")
		systray.SetIcon(app.trayIcons["warning"])
	case stateCertificateOK:
		// check we haven't expired
		if !app.client.CertificateValid() {
			app.logger.Info("current certificate expired")

			// try to refresh
			if err := app.refreshWithBackoff(); err == nil {
				app.logger.Info("refresh of certificate succeeded")
				// send notification
				app.notify("Cerificate Refreshed", "The current certificate was successfully refreshed", okIcon)
				// re-run to handle change
				app.setState()
				// finish now
				break
			} else {
				// return if renewal is in progress
				if errors.Is(err, ErrRenewRunning) {
					break
				}

				if errors.Is(err, ErrRenewSkipped) {
					app.logger.Error("expired certificate was not renewed due to recent failures", "failures", app.refreshFailure, "backoff", app.refreshBackOff)
				} else {
					app.logger.Error("could not refresh expired certificate", "error", err, "failures", app.refreshFailure, "backoff", app.refreshBackOff)
				}
			}

			app.state = stateCertificateExpired
			// send notification
			app.notify("Cerificate Expired", "The current certificate has expired and must be manually renewed", warningIcon)
			// re-run to handle change
			app.setState()
			// finish now
			break
		}

		// check if the renewAt threshold has been reached
		if time.Until(app.client.CerificateExpiry()) < app.renewAt {
			app.logger.Info("current certificate close to expiry")

			// try to refresh
			if err := app.refreshWithBackoff(); err == nil {
				app.logger.Info("refresh of certificate succeeded")
				// send notification
				app.notify("Cerificate Refreshed", "The current certificate was successfully refreshed", okIcon)
				// re-run to handle change
				app.setState()
				// finish now
				break
			} else {
				// return if renewal is in progress
				if errors.Is(err, ErrRenewRunning) {
					break
				}

				// just log error
				if errors.Is(err, ErrRenewSkipped) {
					app.logger.Error("certificate near expiry was not renewed due to recent failures", "failures", app.refreshFailure, "backoff", app.refreshBackOff)
				} else {
					app.logger.Error("could not refresh certificate close to expiry", "error", err, "failures", app.refreshFailure, "backoff", app.refreshBackOff)
				}
			}
		}

		app.mRenew.SetTitle("Renew")
		app.mRenew.Enable()
		app.mExpiry.SetTitle(fmt.Sprintf("%s left", timeLeft(app.client.CerificateExpiry())))
		setTooltip("Current certificate valid")
		systray.SetIcon(app.trayIcons[okIcon])
	}
}

func (app *Application) eventloop() {
	t := time.NewTicker(time.Minute * 1)
	for {
		app.setState()

		select {
		case <-t.C:
			// this is a noop
			continue
		case <-app.mRenew.ClickedCh:
			// start by disabling menu item so we aren't overlapping
			app.mRenew.Disable()

			// try refresh first
			if err := app.refresh(); err != nil {
				// skip interactive flow if error was related to ssh agent
				if errors.Is(err, client.ErrAddingToAgent) || errors.Is(err, client.ErrConnectingToAgent) {
					app.logger.Warn("certificate refreshed but could not add to agent", "error", err)
					app.notify("Warning", "Certificate renewed byt could not add to SSH Agent", warningIcon)
				}
				// then do interactive renewal
				app.logger.Warn("could not perform a refresh, running renew", "error", err)
				if err := app.renew(); err != nil {
					app.logger.Error("could not renew certificate", "error", err)
					app.notify("Error", "The certificate renewal failed", errorIcon)
					break
				}
			}

			app.notify("Certificate Issued", "A new certificate was issued and added to the local ssh-agent", okIcon)
			app.state = stateCertificateOK
		case <-app.mGenerate.ClickedCh:
			// start by disabling menu item so we aren't overlapping
			app.mGenerate.Disable()

			// do key generation
			if err := app.generate(); err != nil {
				app.logger.Error("could not generate private key", "error", err)
				app.notify("Error", "The generation of a private key failed", errorIcon)
				break
			}

			app.notify("Key Generated", "A private key was sucessfully generated", okIcon)
			app.state = stateKeyOK
		case <-app.mQuit.ClickedCh:
			app.logger.Info("application shutting down")
			t.Stop()
			systray.Quit()
			return
		}
	}
}

func (app *Application) refreshWithBackoff() error {
	// try to take lock and error immediately if we cant
	if !app.mu.TryLock() {
		return ErrRenewRunning
	}
	defer app.mu.Unlock()

	if app.refreshBackOff > 0 {
		// reduce our backoff counter
		app.refreshBackOff--

		// exit
		return ErrRenewSkipped
	}

	// we are ok to attempt a refresh
	if err := app.client.Refresh(); err != nil {
		// increment our failure count and set a backoff of double our failure count
		app.refreshFailure++
		app.refreshBackOff = app.refreshFailure * 2

		return err
	}

	// reset on success
	app.refreshFailure = 0
	app.refreshBackOff = 0

	return nil
}

func (app *Application) refresh() error {
	// try to take lock and error immediately if we cant
	if !app.mu.TryLock() {
		return ErrRenewRunning
	}
	defer app.mu.Unlock()

	app.logger.Info("attempting a refresh")

	if err := app.client.Refresh(); err != nil {
		return err
	}

	// reset on success
	app.refreshFailure = 0
	app.refreshBackOff = 0

	return nil
}

func (app *Application) renew() error {
	// try to take lock and error immediately if we cant
	if !app.mu.TryLock() {
		return ErrRenewRunning
	}
	defer app.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	if err := app.client.ExecuteLoginWithContext(ctx, app.addr); err != nil {
		return err
	}

	// reset on success
	app.refreshFailure = 0
	app.refreshBackOff = 0

	return nil
}

func (app *Application) generate() error {
	return app.client.GenerateKey()
}

func timeLeft(t time.Time) string {
	timeLeft := time.Until(t)
	return fmt.Sprintf("%02dh%02dm", int(timeLeft.Hours()), int(timeLeft.Minutes())%60)
}

func setTooltip(message string) {
	version := "Unknown"

	// get version if available
	info, ok := debug.ReadBuildInfo()
	if ok {
		version = info.Main.Version
	}

	// set tooltip
	tooltip := fmt.Sprintf("SSH CA Client (%s) - %s", version, message)
	systray.SetTooltip(tooltip)
}
