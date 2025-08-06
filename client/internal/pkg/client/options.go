package client

import (
	"log/slog"
	"net/http"
	"time"
)

// Options for [*LoginHandler]
type LoginHandlerOption func(*LoginHandler)

// WithLifetime sets a different lifetime than [DefaultLifetime]
func WithLifetime(lifetime time.Duration) LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.lifetime = lifetime
	}
}

// SkipAgent sets the login process to skip adding the key and certificate
// to the users local SSH agent
func SkipAgent() LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.skipAgent = true
	}
}

// ShowTokens will display/log the tokens returned from the OIDC login/refresh
// process. This is designed as a debugging tool rather than something that is
// enabled by default
func ShowTokens() LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.showTokens = true
	}
}

// WithServer allows using a custom [*http.Server] instead of the default
func WithServer(srv *http.Server) LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.srv = srv
	}
}

// By default [NewLoginHandler] will return a [ErrNoPrivateKey] error if no
// private private key exists, however passing the AllowWithoutKey
// [LoginHandlerOption] to [NewLoginHandler] will skip this check
func AllowWithoutKey() LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.allowWithoutKey = true
	}
}

// WithLogger allows providing a custom [*slog.Logger] for the service
func WithLogger(logger *slog.Logger) LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.logger = logger
	}
}
