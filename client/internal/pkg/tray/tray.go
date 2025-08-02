package tray

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"image/png"
	"log/slog"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	"github.com/gen2brain/beeep"
	"github.com/getlantern/systray"
	"github.com/sergeymakinen/go-ico"
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
)

type Application struct {
	client *client.LoginHandler
	done   chan bool
	title  string
	addr   string

	icon             []byte
	notificationIcon []byte
	state            appState

	mGenerate *systray.MenuItem
	mRenew    *systray.MenuItem
	mQuit     *systray.MenuItem

	logger *slog.Logger
}

func New(title, addr string, fs embed.FS, client *client.LoginHandler) (*Application, error) {
	// load smaller image for tray icon
	f, err := fs.Open("icons/app-256.png")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	img, err := png.Decode(f)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err := ico.Encode(buf, img); err != nil {
		return nil, err
	}

	// load larger icon for notifications
	nb, err := fs.ReadFile("icons/app-512.png")
	if err != nil {
		return nil, err
	}

	return &Application{
		addr:             addr,
		done:             make(chan bool),
		client:           client,
		title:            title,
		icon:             buf.Bytes(),
		notificationIcon: nb,
		state:            stateInit,
		logger:           slog.Default(),
	}, nil
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
	systray.SetIcon(app.icon)

	// buildmenu
	app.mRenew = systray.AddMenuItem("Renew", "Renew certificate")
	app.mGenerate = systray.AddMenuItem("Generate", "Generate private key")
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
		app.logger.Info("starting application")
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
		systray.SetTooltip("No private key found")
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

		// fallthrough to handle change
		fallthrough
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
		systray.SetTooltip("Certificate expired")
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
		systray.SetTooltip("No certificate found")
	case stateCertificateOK:
		// check we haven't expired
		if !app.client.CertificateValid() {
			app.logger.Info("current certificate expired")
			app.state = stateCertificateExpired
			// send notification
			app.notify("Cerificate Expired", "The current certificate has expired and must be renewed")
			// re-run to handle change
			app.setState()
			// finish now
			break
		}
		app.mRenew.SetTitle("Renew Early")
		app.mRenew.Enable()
		systray.SetTooltip(fmt.Sprintf("Current certificate valid (%s left)", timeLeft(app.client.CerificateExpiry())))
	}
}

func (app *Application) eventloop() {
	t := time.NewTicker(time.Minute * 1)
	for {
		app.setState()

		select {
		case <-t.C:

		case <-app.mRenew.ClickedCh:
			// start by disabling menu item so we aren't overlapping
			app.mRenew.Disable()

			// do renewal
			if err := app.renew(); err != nil {
				app.logger.Error("could not request certificate", "error", err)
				app.notify("Error", "The certificate request failed.")
				continue
			}

			app.notify("Certificate Issued", "A new certificate was issued and added to the local ssh-agent")
			continue
		case <-app.mGenerate.ClickedCh:
			// start by disabling menu item so we aren't overlapping
			app.mGenerate.Disable()

			// do key generation
			if err := app.generate(); err != nil {
				app.logger.Error("could not generate certificate", "error", err)
				app.notify("Error", "The generation of a private key failed.")
				continue
			}

			app.notify("Key Generated", "A private key was sucessfully generated")
			continue
		case <-app.mQuit.ClickedCh:
			t.Stop()
			systray.Quit()
			return
		}
	}
}

func (app *Application) renew() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	return app.client.ExecuteLoginWithContext(ctx, app.addr)
}

func (app *Application) generate() error {
	return app.client.GenerateKey()
}

func (app *Application) notify(title string, message string) {
	if err := beeep.Notify(title, message, app.notificationIcon); err != nil {
		app.logger.Error("could not send notification", "error", err)
	}
}

func timeLeft(t time.Time) string {
	timeLeft := time.Until(t)
	return fmt.Sprintf("%02dh%02dm", int(timeLeft.Hours()), int(timeLeft.Minutes())%60)
}
