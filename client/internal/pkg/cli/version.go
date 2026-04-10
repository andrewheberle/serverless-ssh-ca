package cli

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/version"
	"github.com/andrewheberle/simplecommand"
	"github.com/bep/simplecobra"
)

type versionCommand struct {
	json bool

	*simplecommand.Command
}

type versionJson struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (c *versionCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.json, "json", false, "Output as JSON")

	return nil
}

func (c *versionCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	return showversion(cd.Root.Command.Name(), c.json)
}

func showversion(name string, asjson bool) error {
	if asjson {
		return json.NewEncoder(stdout).Encode(versionJson{Name: name, Version: version.Version()})
	}

	_, err := fmt.Fprintf(stdout, "%s %s\n", name, version.Version())

	return err
}
