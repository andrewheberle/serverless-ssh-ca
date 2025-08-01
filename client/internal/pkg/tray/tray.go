package tray

import (
	"bytes"
	"context"
	"embed"
	"image/png"
	"log/slog"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	"github.com/gen2brain/beeep"
	"github.com/getlantern/systray"
	"github.com/qmuntal/stateless"
	"github.com/sergeymakinen/go-ico"
)

type certificateState int

const (
	stateInit certificateState = iota
	stateKeyNotFound
	stateKeyFound
	triggerCheckPrivateKey
	triggerGeneratePrivateKey
	triggerCheckCertificate
)

type Application struct {
	client *client.LoginHandler
	done   chan bool
	title  string
	addr   string

	icon             []byte
	notificationIcon []byte
	state            *stateless.StateMachine

	mGenerate *systray.MenuItem
	mRenew    *systray.MenuItem
	mQuit     *systray.MenuItem
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
	}, nil
}

func (app *Application) Run() {
	// set up state machine
	app.state = app.stateMachine()

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

	// handle clicks
	go app.eventloop()
}

func (app *Application) setState() {
	switch {
	case !app.client.HasPrivateKey():
		app.mGenerate.Enable()
		app.mRenew.Disable()
		systray.SetTooltip("No private key found")
	case app.client.HasPrivateKey():
		app.mGenerate.Disable()
		app.mRenew.Enable()
		if app.client.CertificateValid() {
			app.mRenew.SetTitle("Renew")
			systray.SetTooltip("Current certificate valid")
		} else {
			app.mRenew.SetTitle("Request")
			systray.SetTooltip("Certificate missing or not found")
		}
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
				slog.Error("could not request certificate", "error", err)
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
				slog.Error("could not generate certificate", "error", err)
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
		slog.Error("could not send notification", "error", err)
	}
}

func (app *Application) stateMachine() *stateless.StateMachine {
	// set up state machine
	state := stateless.NewStateMachine(stateInit)
	state.Configure(stateInit).Permit(triggerCheckPrivateKey, stateKeyNotFound)

	// from init -> stateKeyNotFound -> stateKeyFound
	state.Configure(stateKeyNotFound).
		OnEntryFrom(stateInit, func(_ context.Context, args ...any) error {
			app.notify("Missing Private Key", "No private key was found. No certificates can be requested until this is generated.")
			app.mRenew.Disable()
			app.mGenerate.Enable()
			systray.SetTooltip("No private key found")
			return nil
		}).
		Permit(triggerGeneratePrivateKey, stateKeyFound)
	// from init -> stateKeyFound
	state.Configure(stateKeyFound).
		OnEntryFrom(stateInit, func(_ context.Context, args ...any) error {
			app.mRenew.Disable()
			app.mGenerate.Disable()
			state.Fire(triggerCheckCertificate)
			return nil
		})

	return state
}
