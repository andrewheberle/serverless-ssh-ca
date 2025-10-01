package device

import (
	"log/slog"
	"net/http"
	"time"
)

// Options for [*DeviceLoginHandler]
type DeviceLoginHandlerOption func(*DeviceLoginHandler)

// WithLifetime sets a different lifetime than [DefaultLifetime]
func WithLifetime(lifetime time.Duration) DeviceLoginHandlerOption {
	return func(lh *DeviceLoginHandler) {
		lh.lifetime = lifetime
	}
}

// WithServer allows using a custom [*http.Server] instead of the default
func WithServer(srv *http.Server) DeviceLoginHandlerOption {
	return func(lh *DeviceLoginHandler) {
		lh.srv = srv
	}
}

// By default [NewLoginHandler] will return a [ErrNoPrivateKey] error if no
// private private key exists, however passing the AllowWithoutKey
// [DeviceLoginHandlerOption] to [NewDeviceLoginHandler] will skip this check
func AllowWithoutKey() DeviceLoginHandlerOption {
	return func(lh *DeviceLoginHandler) {
		lh.allowWithoutKey = true
	}
}

// WithLogger allows providing a custom [*slog.Logger] for the service
func WithLogger(logger *slog.Logger) DeviceLoginHandlerOption {
	return func(lh *DeviceLoginHandler) {
		lh.logger = logger
	}
}
