package tray

import (
	"errors"
	"log/slog"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	"github.com/getlantern/systray"
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

var (
	ErrNotSupported = errors.New("this is not currently supported on your OS")
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
