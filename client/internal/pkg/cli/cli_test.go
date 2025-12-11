package cli_test

import (
	"context"
	"testing"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/cli"
)

func TestExecute(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{"no args", []string{}, false},
		{"generate sub-command", []string{"--config", "testdata/system.yml", "generate", "--dryrun"}, false},
		{"generate sub-command should ignore system config", []string{"--config", "testdata/missing.yml", "generate", "--dryrun"}, false},
		{"host sub-command with non-existent key", []string{"--config", "testdata/system.yml", "host", "--key", "missing_key"}, true},
		{"show sub-command", []string{"--config", "testdata/system.yml", "show", "--status"}, false},
		{"show sub-command should ignore missing system config", []string{"--config", "testdata/missing.yml", "show", "--status"}, false},
		{"show --private sub-command should error with missing user config", []string{"--user", "missing.yml", "show", "--private"}, true},
		{"show --public sub-command should error with missing user config", []string{"--user", "missing.yml", "show", "--public"}, true},
		{"show --certificate sub-command should error with missing user config", []string{"--user", "missing.yml", "show", "--certificate"}, true},
		{"login sub-command should error with missing system config", []string{"--config", "missing.yml", "login"}, true},
		{"version sub-command", []string{"version"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := cli.Execute(context.Background(), tt.args)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Execute() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Execute() succeeded unexpectedly")
			}
		})
	}
}
