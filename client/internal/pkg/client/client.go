package client

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
	"runtime"
	"runtime/debug"
	"sync"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/sshcert"
	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/sshkey"
	"github.com/andrewheberle/sshagent"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/ndbeals/winssh-pageant/pageant"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

type CertificateSignerPayload struct {
	Lifetime  int    `json:"lifetime"`
	PublicKey []byte `json:"public_key"`
	Identity  string `json:"identity,omitempty"`
	Nonce     string `json:"nonce"`
}

type CertificateSignerResponse struct {
	Certificate []byte `json:"certificate"`
}

type LoginHandler struct {
	showTokens       bool
	skipAgent        bool
	srv              *http.Server
	started          bool
	verifier         *oidc.IDTokenVerifier
	oauth2Config     oauth2.Config
	store            *sessions.CookieStore
	config           *config.Config
	lifetime         time.Duration
	redirectURL      *url.URL
	done             chan error
	pageantProxyDone chan bool
	logger           *slog.Logger
	allowWithoutKey  bool
	pageantProxy     bool
	mu               sync.RWMutex
}

const (
	DefaultLifetime = time.Hour * 24
	UserAgent       = "Serverless-SSH-CA-Client"
)

var (
	ErrNoPrivateKey           = config.ErrNoPrivateKey
	ErrAlreadyStarted         = errors.New("server has already started")
	ErrNotStarted             = errors.New("server has not been started")
	ErrPageantProxyNotEnabled = errors.New("pageant proxy not enabled")
	ErrConnectingToAgent      = errors.New("could not connect to agent")
	ErrAddingToAgent          = errors.New("could not add to agent")
	ErrCertificateNotValid    = errors.New("certificate validity not ok")

	// DefaultLogger is the default [*slog.Logger] used
	DefaultLogger = slog.Default()

	userAgentFull = getUserAgent(UserAgent)
)

// NewLoginHandler creates a new handler
func NewLoginHandler(system, user string, opts ...LoginHandlerOption) (*LoginHandler, error) {
	// load config
	config, err := config.LoadConfig(system, user)
	if err != nil {
		return nil, err
	}

	// set up oidc provider
	provider, err := oidc.NewProvider(context.Background(), config.Oidc().Issuer)
	if err != nil {
		return nil, err
	}

	// set redirectURL
	redirectURL, err := url.Parse(config.Oidc().RedirectURL)
	if err != nil {
		return nil, err
	}

	// set defaults
	lh := &LoginHandler{
		config:   config,
		lifetime: DefaultLifetime,
		store:    sessions.NewCookieStore(securecookie.GenerateRandomKey(32)),
		verifier: provider.Verifier(&oidc.Config{ClientID: config.Oidc().ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:    config.Oidc().ClientID,
			RedirectURL: config.Oidc().RedirectURL,
			Endpoint:    provider.Endpoint(),
			Scopes:      config.Oidc().Scopes,
		},
		redirectURL:      redirectURL,
		done:             make(chan error),
		pageantProxyDone: make(chan bool),
		logger:           DefaultLogger,
	}

	// set from options
	for _, o := range opts {
		o(lh)
	}

	// check we have a key and this is fatal
	if !config.HasPrivateKey() && !lh.allowWithoutKey {
		return nil, ErrNoPrivateKey
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

// HasPrivateKey returns true or false if a SSH private key exists
func (lh *LoginHandler) HasPrivateKey() bool {
	return lh.config.HasPrivateKey()
}

// GenerateKey will generate a new SSH private key
func (lh *LoginHandler) GenerateKey() error {
	// set comment based on user@host if possible
	user := "nobody"
	host := "nowhere"
	if u := os.Getenv("USERNAME"); u != "" {
		user = u
	} else if u := os.Getenv("USER"); u != "" {
		user = u
	}
	if h := os.Getenv("COMPUTERNAME"); h != "" {
		host = h
	}

	// generate private key
	pemBytes, err := sshkey.GenerateKey(user + "@" + host)
	if err != nil {
		return err
	}

	// save private key
	return lh.config.SetPrivateKeyBytes(pemBytes)
}

// Start performs ListenAndServe() for the login handler HTTP service
// however unlike [*http.Server.ListenAndServe()] this will return
// immediately so you should run [*LoginHandler.Wait()] after.
//
// If the server has already started this will return [ErrAlreadyStarted]
func (lh *LoginHandler) Start(address string) error {
	lh.mu.Lock()
	defer lh.mu.Unlock()

	if lh.started {
		return ErrAlreadyStarted
	}

	lh.srv.Addr = address
	lh.started = true
	lh.done = make(chan error)
	go func() {
		// make sure to set we are no longer running when this completes
		defer func() {
			lh.started = false
		}()

		// run in a goroutine so this returns immediately
		lh.done <- lh.srv.ListenAndServe()
	}()

	return nil
}

// Wait will block until the provided context completes or the login handler
// HTTP service is stopped via [*LoginHandler.Shutdown()].
//
// If the service has not been started this will return [ErrNotStarted]
func (lh *LoginHandler) Wait(ctx context.Context) error {
	if !lh.mu.TryRLock() {
		return ErrAlreadyStarted
	}
	defer lh.mu.RUnlock()

	if !lh.started {
		return ErrNotStarted
	}

	select {
	case err := <-lh.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown gracefully shuts down the HTTP service
func (lh *LoginHandler) Shutdown() error {
	// shut down the service
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	// shutdown and send result to channel
	lh.logger.Info("shutting down web server")
	err := lh.srv.Shutdown(ctx)
	lh.done <- err
	close(lh.done)

	// also return result
	return err
}

// RunPageantProxy will proxy PuTTY Agent connections to the native OpenSSH
// SSH Agent.
//
// This will block until the provided context is complete or
// [*LoginHandler.ShutdownPageantProxy()] is run.
func (lh *LoginHandler) RunPageantProxy(ctx context.Context) error {
	if !lh.pageantProxy {
		return ErrPageantProxyNotEnabled
	}

	// start as a goroutine
	go func() {
		p := pageant.NewDefaultHandler(`\\.\pipe\openssh-ssh-agent`, true)
		p.Run()
	}()

	// block here until context is finished or ShutdownPageantProxy is run
	select {
	case <-lh.pageantProxyDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ShutdownPageantProxy will shutdown a running PuTTY Agent proxy.
func (lh *LoginHandler) ShutdownPageantProxy() {
	lh.pageantProxyDone <- true
	close(lh.pageantProxyDone)
}

// RedirectPath returns the redirect path for the configured OIDC IdP
func (lh *LoginHandler) RedirectPath() string {
	return lh.redirectURL.Path
}

// The Login method is intended for use as the handler function for
// the intial login URL of the OIDC auth flow process as part of the Serverless
// SSH CA.
//
// This will start the OIDC auth flow process and redirect the user to
// the configured OIDC IdP.
func (lh *LoginHandler) Login(w http.ResponseWriter, r *http.Request) {
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
func (lh *LoginHandler) Callback(w http.ResponseWriter, r *http.Request) {
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

func (lh *LoginHandler) doLogin(token *oauth2.Token) error {
	// extract id token
	rawIDToken, _ := token.Extra("id_token").(string)

	// show tokens now
	if lh.showTokens {
		lh.logger.Info("the following tokens were received",
			"id_token", rawIDToken,
			"access_token", token.AccessToken,
			"refresh_token", token.RefreshToken,
		)
	}

	// if we got a refresh token then save it
	if token.RefreshToken != "" {
		if err := lh.config.SetRefreshToken(token.RefreshToken); err != nil {
			lh.logger.Warn("could not save refresh token", "error", err)
		} else {
			lh.logger.Info("saved the provided refresh token for subsequent renewals")
		}
	}

	cert, err := lh.doSigningRequest(token.AccessToken, rawIDToken)
	if err != nil {
		return err
	}

	// add and save the config
	if err := lh.config.SetCertificateBytes(cert.Certificate); err != nil {
		return err
	}

	// finish here if skip option was provided
	if lh.skipAgent {
		return nil
	}

	if err := lh.AddToAgent(); err != nil {
		return err
	}

	return nil
}

func (lh *LoginHandler) AddToAgent() error {
	keyBytes, err := lh.config.GetPrivateKeyBytes()
	if err != nil {
		return err
	}
	defer clearBytes(keyBytes)

	key, err := sshkey.ParseKey(keyBytes)
	if err != nil {
		return err
	}

	certBytes, err := lh.config.GetCertificateBytes()
	if err != nil {
		return err
	}

	cert, err := sshcert.ParseCert(certBytes)
	if err != nil {
		return err
	}

	// check validity (with 5-seconds grace time on ValidAfter as certificate could be issued with +1 seconds from now ValidAfter)
	now := time.Now().Unix()
	if now > int64(cert.ValidBefore) || now < int64(cert.ValidAfter-5) {
		lh.logger.Error("certificate was not valid so not adding to agent", "validbefore", cert.ValidBefore, "validafter", cert.ValidAfter, "now", now)
		return ErrCertificateNotValid
	}

	agentClient, err := sshagent.NewAgent()
	if err != nil {
		return ErrConnectingToAgent
	}

	if err := agentClient.Add(addedKey(key, cert)); err != nil {
		return ErrAddingToAgent
	}

	return nil
}

// Refresh attempts to refresh the authentication and identity token
func (lh *LoginHandler) Refresh() error {
	// try refresh token
	refresh, err := lh.config.GetRefreshToken()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	tokenSource := lh.oauth2Config.TokenSource(ctx, &oauth2.Token{
		RefreshToken: refresh,
	})

	// try to obtain a new auth token
	token, err := tokenSource.Token()
	if err != nil {
		return err
	}

	return lh.doLogin(token)
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

func (lh *LoginHandler) doSigningRequest(access, id string) (*CertificateSignerResponse, error) {
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
		Identity:  id,
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

func (lh *LoginHandler) generateNonce() (string, error) {
	// get signer
	signer, err := lh.config.Signer()
	if err != nil {
		return "", err
	}

	// generate data to sign
	timestamp := time.Now().UnixMilli()
	fingerprint := ssh.FingerprintSHA256(signer.PublicKey())
	dataToSign := fmt.Sprintf("%d.%s", timestamp, fingerprint)

	// sign data
	signature, err := signer.Sign(rand.Reader, []byte(dataToSign))
	if err != nil {
		return "", err
	}

	// return encoded data
	return fmt.Sprintf("%s.%s", dataToSign, base64.StdEncoding.EncodeToString(signature.Blob)), nil
}

// ExecuteLogin performs [*LoginHandler.Start()], attempts to open the users
// browser to start the OIDC auth flow, followed by [*LoginHandler.Wait()]
func (lh *LoginHandler) ExecuteLogin(addr string) error {
	return lh.executeLogin(context.Background(), addr)
}

// ExecuteLoginWithContext is identitical to [*LoginHandler.ExecuteLogin()]
// however the provided context is used rather than the default of
// [context.Background()]
func (lh *LoginHandler) ExecuteLoginWithContext(ctx context.Context, addr string) error {
	return lh.executeLogin(ctx, addr)
}

func (lh *LoginHandler) executeLogin(ctx context.Context, addr string) error {
	// start web server now
	lh.logger.Info("starting web server", "address", addr)
	if err := lh.Start(addr); err != nil {
		return err
	}

	// at this point do interactive login flow
	loginUrl := fmt.Sprintf("http://%s/auth/login", addr)
	if err := util.OpenUrl(loginUrl); err != nil {
		lh.logger.Error("could not open browser, please visit URL manually", "url", loginUrl)
	}

	lh.logger.Info("starting interactive login flow", "url", loginUrl)

	// wait here until done
	if err := lh.Wait(ctx); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return err
	}

	return nil
}

func (lh *LoginHandler) HasCertificate() bool {
	return lh.config.HasCertificate()
}

func (lh *LoginHandler) CertificateValid() bool {
	return lh.config.CertificateValid()
}

func (lh *LoginHandler) CerificateExpiry() time.Time {
	return lh.config.CerificateExpiry()
}

// SetLogger sets the [*slog.Logger] used after the [*LoginHandler] has been
// created by [NewHandler]
func (lh *LoginHandler) SetLogger(logger *slog.Logger) {
	lh.logger = logger
}

// OIDCConfig shows the current underlying OIDC config
func (lh *LoginHandler) OIDCConfig() config.ClientOIDCConfig {
	return lh.config.Oidc()
}

// CertificateAuthorityURL shows the CA URL
func (lh *LoginHandler) CertificateAuthorityURL() string {
	return lh.config.CertificateAuthorityURL()
}

func getUserAgent(name string) string {
	version := "Unknown"

	// get version if available
	info, ok := debug.ReadBuildInfo()
	if ok {
		version = info.Main.Version
	}

	return fmt.Sprintf("%s/%s (%s-%s)", name, version, runtime.GOOS, runtime.GOARCH)
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
