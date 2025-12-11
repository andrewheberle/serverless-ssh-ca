package host

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/client"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

const (
	DefaultLifetime = (time.Hour * 24) * 30
)

var (
	ErrNoKeys                 = errors.New("no SSH host keys found")
	ErrAlreadyStarted         = errors.New("server has already started")
	ErrNotStarted             = errors.New("server has not been started")
	ErrPageantProxyNotEnabled = errors.New("pageant proxy not enabled")
	ErrConnectingToAgent      = errors.New("could not connect to agent")
	ErrAddingToAgent          = errors.New("could not add to agent")
	ErrCertificateNotValid    = errors.New("certificate validity not ok")

	// DefaultLogger is the default [*slog.Logger] used
	DefaultLogger = slog.Default()

	userAgentFull = client.GenerateUserAgent(client.UserAgent)
)

type CertificateSignerPayload struct {
	Lifetime   int      `json:"lifetime"`
	Principals []string `json:"principals"`
	PublicKey  []byte   `json:"public_key"`
	Nonce      string   `json:"nonce"`
}

type CertificateSignerResponse struct {
	Certificate []byte `json:"certificate"`
}

type HostLoginHandler struct {
	key          interface{}
	srv          *http.Server
	started      bool
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	store        *sessions.CookieStore
	config       *config.SystemConfig
	lifetime     time.Duration
	redirectURL  *url.URL
	done         chan error
	logger       *slog.Logger
	mu           sync.RWMutex
}

// NewLoginHandler creates a new handler
func NewHostLoginHandler(keypath string, config *config.SystemConfig, opts ...HostLoginHandlerOption) (*HostLoginHandler, error) {
	// check key exists
	b, err := os.ReadFile(keypath)
	if err != nil {
		return nil, err
	}

	// parse key
	key, err := ssh.ParseRawPrivateKey(b)
	if err != nil {
		return nil, err
	}

	// set up oidc provider
	provider, err := oidc.NewProvider(context.Background(), config.Issuer)
	if err != nil {
		return nil, err
	}

	// set redirectURL
	redirectURL, err := url.Parse(config.RedirectURL)
	if err != nil {
		return nil, err
	}

	// set defaults
	lh := &HostLoginHandler{
		key:      key,
		config:   config,
		lifetime: DefaultLifetime,
		store:    sessions.NewCookieStore(securecookie.GenerateRandomKey(32)),
		verifier: provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:    config.ClientID,
			RedirectURL: config.RedirectURL,
			Endpoint:    provider.Endpoint(),
			Scopes:      config.Scopes,
		},
		redirectURL: redirectURL,
		done:        make(chan error),
		logger:      DefaultLogger,
	}

	// set from options
	for _, o := range opts {
		o(lh)
	}

	// set up last resort http server
	if lh.srv == nil {
		// set up our http handler
		mux := http.NewServeMux()
		mux.HandleFunc("/auth/login", lh.Login)
		mux.HandleFunc(lh.RedirectPath(), lh.Callback)

		lh.srv = &http.Server{
			Handler: mux,
		}
	}

	return lh, nil
}

// RedirectPath returns the redirect path for the configured OIDC IdP
func (lh *HostLoginHandler) RedirectPath() string {
	return lh.redirectURL.Path
}

// The Login method is intended for use as the handler function for
// the intial login URL of the OIDC auth flow process as part of the Serverless
// SSH CA.
//
// This will start the OIDC auth flow process and redirect the user to
// the configured OIDC IdP.
func (lh *HostLoginHandler) Login(w http.ResponseWriter, r *http.Request) {
	// store codeVerifier in session
	codeVerifier, codeChallenge := generatePKCE()
	session, _ := lh.store.Get(r, "auth-session")
	session.Values["code_verifier"] = codeVerifier

	// generate random state string and add to session
	b := make([]byte, 128)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "Could not generate random bytes", http.StatusInternalServerError)
		lh.logger.Error("Could not generate random bytes", "error", err)
		return
	}
	state := base64.URLEncoding.EncodeToString(b)
	session.Values["state"] = state

	// save to session
	if err := session.Save(r, w); err != nil {
		http.Error(w, "Could not save session state", http.StatusInternalServerError)
		lh.logger.Error("Could not save session state", "error", err)
		return
	}

	// generate redirect url for auth flow
	authCodeURL := lh.oauth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// redirect to start auth flow
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

// The Callback method is intended for use as the handler function for
// the callback URL of the OIDC auth flow process as part of the Serverless
// SSH CA
func (lh *HostLoginHandler) Callback(w http.ResponseWriter, r *http.Request) {
	defer func() {
		// Put this in a go func so that it will not block process
		go func() {
			// shut down the service
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()

			// wait a while
			time.Sleep(time.Second * 5)

			// shut down
			lh.done <- lh.srv.Shutdown(ctx)
			lh.logger.Info("shut down")
		}()
	}()

	ctx := context.Background()
	code := r.URL.Query().Get("code")

	// load session state
	session, _ := lh.store.Get(r, "auth-session")

	// get state value
	expectedState, ok := session.Values["state"].(string)
	if !ok {
		http.Error(w, "Missing state in session", http.StatusBadRequest)
		lh.logger.Error("Missing state in session")
		return
	}

	// verify state
	if expectedState != r.FormValue("state") {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		lh.logger.Error("State mismatch")
		return
	}

	// retrieve codeVerifier from session
	codeVerifier, ok := session.Values["code_verifier"].(string)
	if !ok {
		http.Error(w, "Missing code_verifier in session", http.StatusBadRequest)
		lh.logger.Error("Missing code_verifier in session")
		return
	}

	// handle token exchange
	token, err := lh.oauth2Config.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		http.Error(w, "Token exchange failed", http.StatusInternalServerError)
		lh.logger.Error("Token exchange failed", "error", err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token found", http.StatusInternalServerError)
		lh.logger.Error("No id_token found")
		return
	}

	if _, err := lh.verifier.Verify(ctx, rawIDToken); err != nil {
		http.Error(w, "Failed to verify ID Token", http.StatusInternalServerError)
		lh.logger.Error("Failed to verify ID Token", "error", err)
		return
	}

	// Signal complete
	_, _ = w.Write([]byte("You may now close this window"))
	lh.logger.Info("completed auth flow")

	// do this in a goroutine so our request returns
	go func() {
		if err := lh.doLogin(token); err != nil {
			lh.logger.Error("error during doLogin", "error", err)
		}
	}()
}

func (lh *HostLoginHandler) doLogin(token *oauth2.Token) error {
	cert, err := lh.doSigningRequest(token.AccessToken)
	if err != nil {
		return err
	}

	// add and save the config
	if err := lh.config.SetCertificateBytes(cert.Certificate); err != nil {
		return err
	}

	return nil
}

type customTransport struct {
	Transport http.RoundTripper
	Headers   map[string]string
}

func (t *customTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	newReq := req.Clone(req.Context())
	if newReq.Header == nil {
		newReq.Header = make(http.Header)
	}
	for key, value := range t.Headers {
		newReq.Header.Set(key, value)
	}

	// Use the underlying transport to execute the request
	return t.transport().RoundTrip(newReq)
}

func (t *customTransport) transport() http.RoundTripper {
	if t.Transport != nil {
		return t.Transport
	}
	return http.DefaultTransport
}

func (lh *HostLoginHandler) doSigningRequest(access string) (*CertificateSignerResponse, error) {
	client := &http.Client{
		Timeout: time.Second * 3,
		Transport: &customTransport{
			Headers: map[string]string{
				"Authorization": "Bearer " + access,
				"User-Agent":    userAgentFull,
			},
		},
	}

	// get public key
	publicKey, err := lh.config.GetPublicKeyBytes()
	if err != nil {
		return nil, err
	}

	// generate nonce
	nonce, err := lh.generateNonce()
	if err != nil {
		return nil, err
	}

	// encode json
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	payload := CertificateSignerPayload{
		PublicKey: publicKey,
		Lifetime:  int(lh.lifetime.Seconds()),
		Nonce:     nonce,
	}
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}

	// build url
	caCertUrl, err := url.JoinPath(lh.config.CertificateAuthorityURL(), "/api/v2/certificate")
	if err != nil {
		return nil, err
	}

	// do POST
	lh.logger.Info("sending request to CA", "url", caCertUrl)
	lh.logger.Debug("certificate request",
		"public_key", payload.PublicKey,
		"lifetime", payload.Lifetime,
		"identity", payload.Identity,
		"nonce", payload.Nonce,
	)
	res, err := client.Post(caCertUrl, "application/json", buf)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = res.Body.Close()
	}()

	// ensure status code was 200 OK
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", res.StatusCode)
	}

	// parse response body
	var csr CertificateSignerResponse
	dec := json.NewDecoder(res.Body)
	if err := dec.Decode(&csr); err != nil {
		return nil, err
	}

	return &csr, nil
}

func generatePKCE() (string, string) {
	b := make([]byte, 90)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	codeVerifier := base64.URLEncoding.EncodeToString(b)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return codeVerifier, codeChallenge
}

func hasKeys() bool {
	keyTypes := []string{"ecdsa", "ed25518", "rsa"}

	for _, t := range keyTypes {
		// if stat gives no error then we found one
		_, err := os.Stat(filepath.Join("/etc/ssh", fmt.Sprintf("ssh_host_%s_key", t)))
		if err == nil {
			return true
		}
	}

	return false
}
