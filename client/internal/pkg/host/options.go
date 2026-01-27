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

// WithRenewal triggers the renewal logic from an existing certificate
func WithRenewal() LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.renewal = true
	}
}

// WithRenewAt sets the threshold from 0-100 for renewals
func WithRenewAt(renewat float64) LoginHandlerOption {
	return func(lh *LoginHandler) {
		if renewat < 0 {
			renewat = 0
		}

		if renewat > 1 {
			renewat = 1
		}

		lh.renewat = renewat
	}
}

// WithDelay sets the delay between requests when handling multiple requests
func WithDelay(delay time.Duration) LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.delay = delay
	}
}
