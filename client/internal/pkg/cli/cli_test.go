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
		{"generate sub-command with missing config", []string{"--config", "testdata/missing.yml", "generate", "--dryrun"}, true},
		{"show sub-command", []string{"--config", "testdata/system.yml", "show", "--status"}, false},
		{"show sub-command with missing config", []string{"--config", "testdata/missing.yml", "show"}, true},
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
