package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/andrewheberle/opkssh-renewer/pkg/sshagent"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/openpubkey/openpubkey/util"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/oauth2"
)

type loginCommand struct {
	skipAgent  bool
	lifetime   time.Duration
	showTokens bool

	srv          *http.Server
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	store        *sessions.CookieStore

	config *config.ClientConfig

	keyPath string

	*simplecommand.Command
}

type certificateSignerPayload struct {
	Lifetime  time.Duration `json:"lifetime"`
	PublicKey []byte        `json:"public_key"`
}

type CertificateSignerResponse struct {
	Certificate []byte `json:"certificate"`
}

func generatePKCE() (string, string) {
	codeVerifier := uuid.New().String()
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return codeVerifier, codeChallenge
}

func (c *loginCommand) Init(cd *simplecobra.Commandeer) error {
	c.Command.Init(cd)

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.skipAgent, "skip-agent", false, "Skip adding SSH key and certificate to ssh-agent")
	cmd.Flags().BoolVar(&c.showTokens, "show-tokens", false, "Display OIDC tokens after login process")
	cmd.Flags().DurationVar(&c.lifetime, "life", time.Hour*24, "Lifetime of SSH certificate")

	return nil
}

func (c *loginCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	c.Command.PreRun(this, runner)

	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return fmt.Errorf("problem accessing root command")
	}
	c.config = root.config

	// check we have a key
	if !c.config.HasPrivateKey() {
		return ErrNoPrivateKey
	}

	config := root.config.Oidc

	// set up oidc provider
	provider, err := oidc.NewProvider(context.Background(), config.Issuer)
	if err != nil {
		return err
	}

	// set up config
	c.oauth2Config = oauth2.Config{
		ClientID:    config.ClientID,
		RedirectURL: config.RedirectURL,
		Endpoint:    provider.Endpoint(),
		Scopes:      config.Scopes,
	}

	// set up verifier
	c.verifier = provider.Verifier(&oidc.Config{ClientID: config.ClientID})

	// set up session storage
	c.store = sessions.NewCookieStore(securecookie.GenerateRandomKey(32))

	redirectURL, err := url.Parse(config.RedirectURL)
	if err != nil {
		return err
	}

	// set up our http handler
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", c.loginHandler)
	mux.HandleFunc(redirectURL.Path, c.callbackHandler)

	// set up our http server
	c.srv = &http.Server{
		Addr:    net.JoinHostPort("localhost", fmt.Sprintf("%d", root.listenPort)),
		Handler: mux,
	}

	return nil
}

func (c *loginCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	// try refresh token
	refresh, err := c.config.GetRefreshToken()
	if err == nil && refresh != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		tokenSource := c.oauth2Config.TokenSource(ctx, &oauth2.Token{
			RefreshToken: refresh,
		})

		// try to obtain a new auth token
		token, err := tokenSource.Token()
		if err == nil {
			if err := c.doLogin(token); err == nil {
				slog.Info("renewed certificate using refresh token")
				return nil
			}

			slog.Error("could not do renewal process via refresh token", "error", err)
		}

		slog.Error("could not renew auth token using refresh token", "error", err)
	}

	// at this point do interactive login flow
	loginUrl := fmt.Sprintf("http://%s/auth/login", c.srv.Addr)
	if err := util.OpenUrl(loginUrl); err != nil {
		slog.Error("could not open browser, please visit URL manually", "url", loginUrl)
	}

	slog.Info("started up", "url", loginUrl)

	if err := c.srv.ListenAndServe(); err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return err
	}

	return nil
}

func (c *loginCommand) loginHandler(w http.ResponseWriter, r *http.Request) {
	codeVerifier, codeChallenge := generatePKCE()

	// Store codeVerifier in session
	session, _ := c.store.Get(r, "auth-session")
	session.Values["code_verifier"] = codeVerifier
	session.Save(r, w)

	// generate redirect url for auth flow
	authCodeURL := c.oauth2Config.AuthCodeURL(
		"state",
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// redirect to start auth flow
	http.Redirect(w, r, authCodeURL, http.StatusFound)
}

func (c *loginCommand) callbackHandler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		// Put this in a go func so that it will not block process
		go func() {
			// shut down the service
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*3)
			defer cancel()

			// wait a while
			time.Sleep(time.Second * 5)

			// shut down
			c.srv.Shutdown(ctx)
			slog.Info("shut down")
		}()
	}()

	ctx := context.Background()
	code := r.URL.Query().Get("code")

	// Retrieve codeVerifier from session
	session, _ := c.store.Get(r, "auth-session")
	codeVerifier, ok := session.Values["code_verifier"].(string)
	if !ok {
		http.Error(w, "Missing code_verifier in session", http.StatusBadRequest)
		slog.Error("Missing code_verifier in session")
		return
	}

	// handle token exchange
	token, err := c.oauth2Config.Exchange(
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

	if _, err := c.verifier.Verify(ctx, rawIDToken); err != nil {
		http.Error(w, "Failed to verify ID Token", http.StatusInternalServerError)
		slog.Error("Failed to verify ID Token", "error", err)
		return
	}

	// Signal complete
	w.Write([]byte("You may now close this window"))
	slog.Info("completed auth flow")

	// do this in a goroutine so our request returns
	go c.doLogin(token)
}

func (c *loginCommand) doLogin(token *oauth2.Token) error {
	// show tokens now
	if c.showTokens {
		rawIDToken, _ := token.Extra("id_token").(string)
		slog.Info("the following tokens were received",
			"id_token", rawIDToken,
			"access_token", token.AccessToken,
			"refresh_token", token.RefreshToken,
		)
	}

	// if we got a refresh token then save it
	if token.RefreshToken != "" {
		if err := c.config.SetRefreshToken(token.RefreshToken); err != nil {
			slog.Warn("could not save refresh token", "error", err)
		} else {
			slog.Info("saved the provided refresh token for subsequent renewals")
		}
	}

	cert, err := c.doSigningRequest(token.AccessToken)
	if err != nil {
		return err
	}

	// add and save the config
	if err := c.config.SetCertificateBytes(cert.Certificate); err != nil {
		return err
	}

	// finish here if skip option was provided
	if c.skipAgent {
		return nil
	}

	if err := c.addToAgent(); err != nil {
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

func (c *loginCommand) doSigningRequest(token string) (*CertificateSignerResponse, error) {
	client := &http.Client{
		Timeout: time.Second * 3,
		Transport: &customTransport{
			Headers: map[string]string{
				"Authorization": "Bearer " + token,
			},
		},
	}

	// get public key
	publicKey, err := c.config.GetPublicKeyBytes()
	if err != nil {
		return nil, err
	}

	// encode json
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(certificateSignerPayload{
		PublicKey: publicKey,
		Lifetime:  time.Duration(c.lifetime.Seconds()),
	}); err != nil {
		return nil, err
	}

	// build url
	caCertUrl, err := url.JoinPath(c.config.Ssh.CertificateAuthorityURL, "/api/v1/certificate")
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

func (c *loginCommand) addToAgent() error {
	keyBytes, err := c.config.GetPrivateKeyBytes()
	if err != nil {
		return err
	}

	key, err := parseKey(keyBytes)
	if err != nil {
		return err
	}

	certBytes, err := c.config.GetCertificateBytes()
	if err != nil {
		return err
	}

	cert, err := parseCert(certBytes)
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

func parseCert(certBytes []byte) (*ssh.Certificate, error) {
	// Parse the certificate.
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH public key/certificate: %w", err)
	}

	// Type assert to *ssh.Certificate. If it's not a certificate, this will fail.
	cert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("the provided key is not a SSH certificate, it is a %T", parsedKey)
	}

	return cert, nil
}

func parseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	privateKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key file: %w", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ECDSA key; its type is %T", privateKey)
	}

	return ecdsaKey, nil
}
