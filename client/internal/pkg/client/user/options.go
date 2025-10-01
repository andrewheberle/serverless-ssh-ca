package user

import (
	"log/slog"
	"net/http"
	"time"
)

// Options for [*UserLoginHandler]
type UserLoginHandlerOption func(*UserLoginHandler)

// WithLifetime sets a different lifetime than [DefaultLifetime]
func WithLifetime(lifetime time.Duration) UserLoginHandlerOption {
	return func(lh *UserLoginHandler) {
		lh.lifetime = lifetime
	}
}

// SkipAgent sets the login process to skip adding the key and certificate
// to the users local SSH agent
func SkipAgent() UserLoginHandlerOption {
	return func(lh *UserLoginHandler) {
		lh.skipAgent = true
	}
}

// ShowTokens will display/log the tokens returned from the OIDC login/refresh
// process. This is designed as a debugging tool rather than something that is
// enabled by default
func ShowTokens() UserLoginHandlerOption {
	return func(lh *UserLoginHandler) {
		lh.showTokens = true
	}
}

// WithServer allows using a custom [*http.Server] instead of the default
func WithServer(srv *http.Server) UserLoginHandlerOption {
	return func(lh *UserLoginHandler) {
		lh.srv = srv
	}
}

// By default [NewLoginHandler] will return a [ErrNoPrivateKey] error if no
// private private key exists, however passing the AllowWithoutKey
// [UserLoginHandlerOption] to [NewUserLoginHandler] will skip this check
func AllowWithoutKey() UserLoginHandlerOption {
	return func(lh *UserLoginHandler) {
		lh.allowWithoutKey = true
	}
}

// WithLogger allows providing a custom [*slog.Logger] for the service
func WithLogger(logger *slog.Logger) UserLoginHandlerOption {
	return func(lh *UserLoginHandler) {
		lh.logger = logger
	}
}

func WithPageantProxy() UserLoginHandlerOption {
	return func(lh *UserLoginHandler) {
		lh.pageantProxy = true
	}
}
