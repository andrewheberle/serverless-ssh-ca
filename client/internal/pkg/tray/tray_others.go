//go:build !windows && !linux

package tray

import (
	"embed"
	"errors"
	"log/slog"
	"runtime"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
)

type Application struct {
}

var ErrNotSupported = errors.New("not supported on this platform")

func New(title, addr string, fs embed.FS, client *client.LoginHandler, renewAt time.Duration) (*Application, error) {
	return nil, ErrNotSupported
}

func (app *Application) RunLogged(logger *slog.Logger) {
	logger.Error("this is not supported on this platform", "goos", runtime.GOOS, "goarch", runtime.GOARCH)
}
