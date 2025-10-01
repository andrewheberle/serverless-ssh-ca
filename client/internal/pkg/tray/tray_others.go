//go:build !windows

package tray

import (
	"embed"
	"errors"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
)

type Application struct{}

var (
	ErrNotSupported = errors.New("not currently supported on your OS")
)

func New(title, addr string, fs embed.FS, client client.LoginHandler) (*Application, error) {
	return nil, ErrNotSupported
}
