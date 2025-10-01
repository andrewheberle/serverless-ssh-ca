package client

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
)

type CertificateSignerPayload struct {
	Lifetime  time.Duration `json:"lifetime"`
	PublicKey []byte        `json:"public_key"`
	Identity  string        `json:"identity,omitempty"`
}

type CertificateSignerResponse struct {
	Certificate []byte `json:"certificate"`
}

type LoginHandler interface {
	HasPrivateKey() bool
	GenerateKey() error
	Start(address string) error
	Wait(ctx context.Context) error
	Shutdown() error
	RunPageantProxy(ctx context.Context) error
	ShutdownPageantProxy()
	RedirectPath() string
	Login(w http.ResponseWriter, r *http.Request)
	Callback(w http.ResponseWriter, r *http.Request)
	Refresh() error
	ExecuteLogin(addr string) error
	ExecuteLoginWithContext(ctx context.Context, addr string) error
	HasCertificate() bool
	CertificateValid() bool
	CerificateExpiry() time.Time
	SetLogger(logger *slog.Logger)
	OIDCConfig() config.ClientOIDCConfig
	CertificateAuthorityURL() string
}

var (
	ErrNoPrivateKey           = config.ErrNoPrivateKey
	ErrNoRefreshToken         = errors.New("no refresh token found")
	ErrAlreadyStarted         = errors.New("server has already started")
	ErrNotStarted             = errors.New("server has not been started")
	ErrPageantProxyNotEnabled = errors.New("pageant proxy not enabled")

	// DefaultLogger is the default [*slog.Logger] used
	DefaultLogger = slog.Default()
)
