//go:build !snap

package version_test

import (
	"testing"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/version"
)

func TestVersion(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		want string
	}{
		{"get devel", "devel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := version.Version()
			if got != tt.want {
				t.Errorf("Version() = %v, want %v", got, tt.want)
			}
		})
	}
}
