package cmd

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/andrewheberle/opkssh-renewer/pkg/sshagent"
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
	skipAgent bool

	srv          *http.Server
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
	store        *sessions.CookieStore

	sshConfig ClientSSHConfig

	keyPath string

	*simplecommand.Command
}

type certificateSignerPayload struct {
	PublicKey []byte `json:"public_key"`
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

	return nil
}

func (c *loginCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	c.Command.PreRun(this, runner)

	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return fmt.Errorf("problem accessing root command")
	}
	c.sshConfig = root.config.Ssh

	// work out key path
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	c.keyPath = filepath.Join(home, ".ssh", c.sshConfig.Name)

	// make sure .ssh dir exists
	if err := os.MkdirAll(filepath.Dir(c.keyPath), 0600); err != nil {
		return err
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
	go func() {
		cert, err := c.doSigningRequest(rawIDToken)
		if err != nil {
			slog.Error("could not complete request to SSH CA", "error", err)
			return
		}

		if err := func() error {
			f, err := os.Create(c.keyPath + "-cert.pub")
			if err != nil {
				slog.Error("could not open file", "error", err)
				return err
			}
			defer f.Close()

			if _, err := f.Write(cert.Certificate); err != nil {
				slog.Error("could not open file", "error", err)
				return err
			}

			return nil
		}(); err != nil {
			return
		}

		// finish here if skip option was provided
		if c.skipAgent {
			return
		}

		if err := c.addToAgent(); err != nil {
			slog.Error("could not add to agent", "error", err)
			return
		}

		slog.Info("added identity and signed certificate to ssh-agent")
	}()
}

func (c *loginCommand) getPublicKey() ([]byte, error) {
	found, err := c.hasPrivateKey()
	if err != nil {
		return nil, err
	}

	if !found {
		slog.Info("no exisiting idenity found")
		pemBytes, err := c.generateKey()
		if err != nil {
			return nil, err
		}

		if err := func() error {
			f, err := os.Create(c.keyPath)
			if err != nil {
				return err
			}
			defer f.Close()

			if _, err := f.Write(pemBytes); err != nil {
				return err
			}

			return nil
		}(); err != nil {
			return nil, err
		}

		key, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, err
		}

		return ssh.MarshalAuthorizedKey(key.PublicKey()), nil
	}

	// load existing key
	pemBytes, err := os.ReadFile(c.keyPath)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return ssh.MarshalAuthorizedKey(key.PublicKey()), nil
}

func (c *loginCommand) hasPrivateKey() (bool, error) {
	info, err := os.Stat(c.keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}

		return false, err
	}

	if info.IsDir() {
		return false, fmt.Errorf("found a directory named: %s", c.sshConfig.Name)
	}

	return true, nil
}

func (c *loginCommand) generateKey() ([]byte, error) {
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

	// generate ECDSA key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// encode to openssh format
	privKey, err := ssh.MarshalPrivateKey(key, user+"@"+host)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(privKey)
	if pemBytes == nil {
		return nil, fmt.Errorf("could not encode key")
	}

	return pemBytes, nil
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
	publicKey, err := c.getPublicKey()
	if err != nil {
		return nil, err
	}

	// encode json
	buf := new(bytes.Buffer)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(certificateSignerPayload{
		PublicKey: publicKey,
	}); err != nil {
		return nil, err
	}

	res, err := client.Post(c.sshConfig.CertificateAuthorityURL, "application/json", buf)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", res.StatusCode)
	}
	defer res.Body.Close()

	dec := json.NewDecoder(res.Body)

	var csr CertificateSignerResponse
	if err := dec.Decode(&csr); err != nil {
		return nil, err
	}

	return &csr, nil
}

func (c *loginCommand) addToAgent() error {
	cert, err := loadcert(c.keyPath + "-cert.pub")
	if err != nil {
		return err
	}

	key, err := loadKey(c.keyPath)
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

func loadKey(name string) (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file %q: %w", name, err)
	}

	privateKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key file: %w", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key from %q is not an ECDSA key; its type is %T", name, privateKey)
	}

	return ecdsaKey, nil
}

func loadpubkey(name string) (ssh.PublicKey, string, error) {
	// Read the content of the file
	keyBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read SSH key/certificate file %q: %w", name, err)
	}

	// Parse the certificate.
	parsedKey, comment, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse SSH public key/certificate from %q: %w", name, err)
	}

	return parsedKey, comment, nil
}

func loadcert(name string) (*ssh.Certificate, error) {
	parsedKey, _, err := loadpubkey(name)
	if err != nil {
		return nil, err
	}

	// Type assert to *ssh.Certificate. If it's not a certificate, this will fail.
	cert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("the provided key in %q is not an SSH certificate, it is a %T", name, parsedKey)
	}

	return cert, nil
}
