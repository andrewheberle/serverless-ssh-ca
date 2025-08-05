//go:build !windows

package tray

import (
	"embed"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
)

type Application struct{}

func New(title, addr string, fs embed.FS, client *client.LoginHandler) (*Application, error) {
	return nil, ErrNotSupported
}
