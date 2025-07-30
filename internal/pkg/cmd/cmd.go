package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"gopkg.in/yaml.v3"
)

type ClienConfig struct {
	Oidc ClientOIDCConfig `yaml:"oidc"`
	Ssh  ClientSSHConfig  `yaml:"ssh"`
}

type ClientOIDCConfig struct {
	Issuer          string   `yaml:"issuer"`
	ClientID        string   `yaml:"client_id"`
	ClientSecret    string   `yaml:"client_secret,omitempty"`
	Scopes          []string `yaml:"scopes"`
	AccessType      string   `yaml:"access_type,omitempty"`
	Prompt          string   `yaml:"prompt,omitempty"`
	RedirectURL     string   `yaml:"redirect_url"`
	SendAccessToken bool     `yaml:"send_access_token,omitempty"`
}

type ClientSSHConfig struct {
	Name                    string `yaml:"name"`
	CertificateAuthorityURL string `yaml:"ca_url"`
}

type rootCommand struct {
	configFile string
	listenPort int

	config ClienConfig

	*simplecommand.Command
}

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	c.Command.Init(cd)

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.PersistentFlags().StringVar(&c.configFile, "config", filepath.Join(home, ".ssh-ca", "config.yml"), "Path to configuration file")
	cmd.PersistentFlags().IntVarP(&c.listenPort, "port", "p", 3000, "Listen port for OIDC auth flow")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	c.Command.PreRun(this, runner)

	f, err := os.Open(c.configFile)
	if err != nil {
		return err
	}
	defer f.Close()

	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&c.config); err != nil {
		return fmt.Errorf("problem parsing config: %w", err)
	}

	return nil
}

func Execute(ctx context.Context, args []string) error {
	rootCmd := &rootCommand{
		Command: simplecommand.New("ssh-ca-client", "A client for a serverless SSH CA"),
	}
	rootCmd.SubCommands = []simplecobra.Commander{
		&loginCommand{
			Command: simplecommand.New("login", "Login via OIDC and request a certificate from CA"),
		},
	}

	// Set up simplecobra
	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	// run command with the provided args
	if _, err := x.Execute(context.Background(), args); err != nil {
		return err
	}

	return nil
}
