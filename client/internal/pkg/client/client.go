package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/sshkey"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/sshcert"
	"github.com/andrewheberle/sshagent"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/oauth2"
)

type CertificateSignerPayload struct {
	Lifetime  time.Duration `json:"lifetime"`
	PublicKey []byte        `json:"public_key"`
	Identity  string        `json:"identity,omitempty"`
}

type CertificateSignerResponse struct {
	Certificate []byte `json:"certificate"`
}

type LoginHandler struct {
	showTokens   bool
	skipAgent    bool
	srv          *http.Server
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	store        *sessions.CookieStore
	config       *config.ClientConfig
	lifetime     time.Duration
	redirectURL  *url.URL
	done         chan error
}

const (
	DefaultLifetime = time.Hour * 24
)

var (
	ErrNoPrivateKey   = config.ErrNoPrivateKey
	ErrNoRefreshToken = errors.New("no refresh token found")
)

func NewLoginHandler(name string, opts ...LoginHandlerOption) (*LoginHandler, error) {
	// load config
	config, err := config.LoadConfig(name)
	if err != nil {
		return nil, err
	}

	// check we have a key
	if !config.HasPrivateKey() {
		return nil, ErrNoPrivateKey
	}

	// set up oidc provider
	provider, err := oidc.NewProvider(context.Background(), config.Oidc.Issuer)
	if err != nil {
		return nil, err
	}

	// set redirectURL
	redirectURL, err := url.Parse(config.Oidc.RedirectURL)
	if err != nil {
		return nil, err
	}

	// set defaults
	lh := &LoginHandler{
		config:   config,
		lifetime: DefaultLifetime,
		store:    sessions.NewCookieStore(securecookie.GenerateRandomKey(32)),
		verifier: provider.Verifier(&oidc.Config{ClientID: config.Oidc.ClientID}),
		oauth2Config: oauth2.Config{
			ClientID:    config.Oidc.ClientID,
			RedirectURL: config.Oidc.RedirectURL,
			Endpoint:    provider.Endpoint(),
			Scopes:      config.Oidc.Scopes,
		},
		redirectURL: redirectURL,
		done:        make(chan error),
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

func (lh *LoginHandler) HasPrivateKey() bool {
	return lh.config.HasPrivateKey()
}

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

func (lh *LoginHandler) Start(address string) {
	lh.srv.Addr = address
	go func() {
		// run in a gorutine so this returns immediately
		lh.done <- lh.srv.ListenAndServe()
	}()
}

func (lh *LoginHandler) Wait(ctx context.Context) error {
	select {
	case <-lh.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (lh *LoginHandler) Shutdown() error {
	// shut down the service
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
	defer cancel()

	// shutdown and send result to channel
	err := lh.srv.Shutdown(ctx)
	lh.done <- err

	// also return result
	return err
}

func (lh *LoginHandler) RedirectPath() string {
	return lh.redirectURL.Path
}

func (lh *LoginHandler) Login(w http.ResponseWriter, r *http.Request) {
	codeVerifier, codeChallenge := generatePKCE()

	// Store codeVerifier in session
	session, _ := lh.store.Get(r, "auth-session")
	session.Values["code_verifier"] = codeVerifier
	session.Save(r, w)

	// generate redirect url for auth flow
	authCodeURL := lh.oauth2Config.AuthCodeURL(
		"state",
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// redirect to start auth flow
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

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
			slog.Info("shut down")
		}()
	}()

	ctx := context.Background()
	code := r.URL.Query().Get("code")

	// Retrieve codeVerifier from session
	session, _ := lh.store.Get(r, "auth-session")
	codeVerifier, ok := session.Values["code_verifier"].(string)
	if !ok {
		http.Error(w, "Missing code_verifier in session", http.StatusBadRequest)
		slog.Error("Missing code_verifier in session")
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
		slog.Error("Token exchange failed", "error", err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token found", http.StatusInternalServerError)
		slog.Error("No id_token found")
		return
	}

	if _, err := lh.verifier.Verify(ctx, rawIDToken); err != nil {
		http.Error(w, "Failed to verify ID Token", http.StatusInternalServerError)
		slog.Error("Failed to verify ID Token", "error", err)
		return
	}

	// Signal complete
	w.Write([]byte("You may now close this window"))
	slog.Info("completed auth flow")

	// do this in a goroutine so our request returns
	go lh.doLogin(token)
}

func (lh *LoginHandler) doLogin(token *oauth2.Token) error {
	// extract id token
	rawIDToken, _ := token.Extra("id_token").(string)

	// show tokens now
	if lh.showTokens {
		slog.Info("the following tokens were received",
			"id_token", rawIDToken,
			"access_token", token.AccessToken,
			"refresh_token", token.RefreshToken,
		)
	}

	// if we got a refresh token then save it
	if token.RefreshToken != "" {
		if err := lh.config.SetRefreshToken(token.RefreshToken); err != nil {
			slog.Warn("could not save refresh token", "error", err)
		} else {
			slog.Info("saved the provided refresh token for subsequent renewals")
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

	if err := lh.addToAgent(); err != nil {
		return err
	}

	return nil
}

func (lh *LoginHandler) addToAgent() error {
	keyBytes, err := lh.config.GetPrivateKeyBytes()
	if err != nil {
		return err
	}

	key, err := sshcert.ParseKey(keyBytes)
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

	agentClient, err := sshagent.NewAgent()
	if err != nil {
		return fmt.Errorf("could not connect to agent: %w", err)
	}

	return agentClient.Add(agent.AddedKey{
		PrivateKey:  key,
		Certificate: cert,
		Comment:     cert.KeyId,
	})
}

func (lh *LoginHandler) Refresh() error {
	// try refresh token
	refresh, err := lh.config.GetRefreshToken()
	if err != nil {
		return err
	}

	if refresh == "" {
		return ErrNoRefreshToken
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
	codeVerifier := uuid.New().String()
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
			},
		},
	}

	// get public key
	publicKey, err := lh.config.GetPublicKeyBytes()
	if err != nil {
		return nil, err
	}

	// encode json
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(CertificateSignerPayload{
		PublicKey: publicKey,
		Lifetime:  time.Duration(lh.lifetime.Seconds()),
		Identity:  id,
	}); err != nil {
		return nil, err
	}

	// build url
	caCertUrl, err := url.JoinPath(lh.config.Ssh.CertificateAuthorityURL, "/api/v1/certificate")
	if err != nil {
		return nil, err
	}

	// do POST
	slog.Info("sending request to CA", "url", caCertUrl)
	res, err := client.Post(caCertUrl, "application/json", buf)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

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

func (lh *LoginHandler) ExecuteLogin(addr string) error {
	return lh.executeLogin(context.Background(), addr)
}

func (lh *LoginHandler) ExecuteLoginWithContext(ctx context.Context, addr string) error {
	return lh.executeLogin(ctx, addr)
}

func (lh *LoginHandler) executeLogin(ctx context.Context, addr string) error {
	// try refresh token
	slog.Info("checking if login can be done using a refresh token")
	if err := lh.Refresh(); err == nil {
		slog.Info("sucessfully renewed certificate using refresh token")
		return nil
	} else {
		slog.Error("could not renew auth token using refresh token", "error", err)
	}

	// start web server now
	slog.Info("starting web server", "address", addr)
	lh.Start(addr)

	// at this point do interactive login flow
	loginUrl := fmt.Sprintf("http://%s/auth/login", addr)
	if err := util.OpenUrl(loginUrl); err != nil {
		slog.Error("could not open browser, please visit URL manually", "url", loginUrl)
	}

	slog.Info("starting interactive login flow", "url", loginUrl)

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
	return lh.config.Ssh.Certificate != nil
}

func (lh *LoginHandler) CertificateValid() bool {
	// get cert bytes, error means invalid
	certBytes, err := lh.config.GetCertificateBytes()
	if err != nil {
		return false
	}

	// parse the cert, errors mean invalid
	cert, err := sshcert.ParseCert(certBytes)
	if err != nil {
		return false
	}

	// make sure not expired
	return time.Now().Unix() < int64(cert.ValidBefore)
}
