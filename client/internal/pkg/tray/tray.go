package tray

import (
	"errors"
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
	ErrNotSupported = errors.New("not currently supported on your OS")
)
