package cmd

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
	"golang.org/x/crypto/ssh"
)

type generateCommand struct {
	force bool

	config *config.ClientConfig

	*simplecommand.Command
}

func (c *generateCommand) Init(cd *simplecobra.Commandeer) error {
	c.Command.Init(cd)

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.force, "force", false, "Force replacing and existing key")

	return nil
}

func (c *generateCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	c.Command.PreRun(this, runner)

	root, ok := this.Root.Command.(*rootCommand)
	if !ok {
		return fmt.Errorf("problem accessing root command")
	}
	c.config = root.config
	return nil
}

func (c *generateCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	if c.config.HasPrivateKey() && !c.force {
		return fmt.Errorf("not overwriting existing private key without force option set")
	}

	pemBytes, err := generateKey()
	if err != nil {
		return err
	}

	if err := c.config.SetPrivateKeyBytes(pemBytes); err != nil {
		return err
	}

	return nil
}

func generateKey() ([]byte, error) {
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
