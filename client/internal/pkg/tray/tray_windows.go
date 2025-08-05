package tray

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	"github.com/gen2brain/beeep"
	"github.com/getlantern/systray"
)

type Application struct {
	client *client.LoginHandler
	done   chan bool
	title  string
	addr   string

	trayIcons         map[string][]byte
	notificationIcons map[string][]byte
	state             appState

	mExpiry   *systray.MenuItem
	mGenerate *systray.MenuItem
	mRenew    *systray.MenuItem
	mQuit     *systray.MenuItem

	logger *slog.Logger
}

func New(title, addr string, fs embed.FS, client *client.LoginHandler) (*Application, error) {
	app := &Application{
		addr:              addr,
		client:            client,
		done:              make(chan bool),
		logger:            slog.New(slog.DiscardHandler),
		notificationIcons: make(map[string][]byte),
		state:             stateInit,
		title:             title,
		trayIcons:         make(map[string][]byte),
	}

	// load tray icons
	tIcons := map[string]string{
		"ok":      "icons/ok.ico",
		"error":   "icons/error.ico",
		"warning": "icons/warning.ico",
	}
	for name, file := range tIcons {
		icon, err := fs.ReadFile(file)
		if err != nil {
			return nil, err
		}

		app.trayIcons[name] = icon
	}

	// load notification icons
	nIcons := map[string]string{
		"ok":      "icons/ok.png",
		"error":   "icons/error.png",
		"warning": "icons/warning.png",
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
	systray.Run(app.onReady, func() {})
}

func (app *Application) RunLogged(logger *slog.Logger) {
	app.logger = logger
	app.client.SetLogger(logger)
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
	app.logger.Info("tray application started")

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
		systray.SetTooltip("No private key found")
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
		systray.SetTooltip("Certificate expired")
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
		systray.SetTooltip("No certificate found")
		systray.SetIcon(app.trayIcons["warning"])
	case stateCertificateOK:
		// check we haven't expired
		if !app.client.CertificateValid() {
			app.logger.Info("current certificate expired")

			// try to refresh
			if err := app.refresh(); err == nil {
				// send notification
				app.notify("Cerificate Refreshed", "The current certificate was successfully refreshed", "ok")
				// re-run to handle change
				app.setState()
				// finish now
				break
			}

			app.state = stateCertificateExpired
			// send notification
			app.notify("Cerificate Expired", "The current certificate has expired and must be manually renewed", "warning")
			// re-run to handle change
			app.setState()
			// finish now
			break
		}
		app.mRenew.SetTitle("Renew Early")
		app.mRenew.Enable()
		app.mExpiry.SetTitle(fmt.Sprintf("%s left", timeLeft(app.client.CerificateExpiry())))
		systray.SetTooltip(fmt.Sprintf("Current certificate valid (%s left)", timeLeft(app.client.CerificateExpiry())))
		systray.SetIcon(app.trayIcons["ok"])
	}
}

func (app *Application) eventloop() {
	t := time.NewTicker(time.Minute * 1)
	for {
		app.setState()

		select {
		case <-t.C:
			// this is just to stop here
			continue
		case <-app.mRenew.ClickedCh:
			// start by disabling menu item so we aren't overlapping
			app.mRenew.Disable()

			// try refresh first
			if err := app.refresh(); err != nil {
				// then do interactive renewal
				if err := app.renew(); err != nil {
					app.logger.Error("could not request certificate", "error", err)
					app.notify("Error", "The certificate request failed", "error")
					continue
				}
			}

			app.notify("Certificate Issued", "A new certificate was issued and added to the local ssh-agent", "ok")
			app.state = stateCertificateOK
		case <-app.mGenerate.ClickedCh:
			// start by disabling menu item so we aren't overlapping
			app.mGenerate.Disable()

			// do key generation
			if err := app.generate(); err != nil {
				app.logger.Error("could not generate private key", "error", err)
				app.notify("Error", "The generation of a private key failed", "error")
				continue
			}

			app.notify("Key Generated", "A private key was sucessfully generated", "ok")
			app.state = stateKeyOK
		case <-app.mQuit.ClickedCh:
			app.logger.Info("application shutting down")
			t.Stop()
			systray.Quit()
			return
		}
	}
}

func (app *Application) refresh() error {
	return app.client.Refresh()
}

func (app *Application) renew() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	return app.client.ExecuteLoginWithContext(ctx, app.addr)
}

func (app *Application) generate() error {
	return app.client.GenerateKey()
}

func (app *Application) notify(title string, message string, icon string) {
	if err := beeep.Notify(title, message, icon); err != nil {
		app.logger.Error("could not send notification", "error", err)
	}
}

func timeLeft(t time.Time) string {
	timeLeft := time.Until(t)
	return fmt.Sprintf("%02dh%02dm", int(timeLeft.Hours()), int(timeLeft.Minutes())%60)
}
