package client

import (
	"net/http"
	"time"
)

type LoginHandlerOption func(*LoginHandler)

func WithLifetime(lifetime time.Duration) LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.lifetime = lifetime
	}
}

func SkipAgent() LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.skipAgent = true
	}
}

func ShowTokens() LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.showTokens = true
	}
}

func WithServer(srv *http.Server) LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.srv = srv
	}
}

func AllowWithoutKey() LoginHandlerOption {
	return func(lh *LoginHandler) {
		lh.allowWithoutKey = true
	}
}
