package host

import (
	"log/slog"
	"time"
)

// Options for [*LoginHandlerOption]
type LoginHandlerOption func(*LoginHandler)

// WithLifetime sets a different lifetime than [DefaultLifetime]
func WithLifetime(lifetime time.Duration) LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.lifetime = lifetime
	}
}

// WithLogger allows providing a custom [*slog.Logger] for the service
func WithLogger(logger *slog.Logger) LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.logger = logger
	}
}

// WithPrincipals allows providing a list of principals for the host certificate
func WithPrincipals(principals []string) LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.principals = principals
	}
}
