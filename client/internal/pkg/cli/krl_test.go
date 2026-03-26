package cli

import (
	"testing"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/config"
)

func Test_krlCommand_getKrlUrl(t *testing.T) {
	tests := []struct {
		name    string // description of this test case
		c       *krlCommand
		want    string
		wantErr bool
	}{
		{"zero value", &krlCommand{config: &config.SystemConfig{}}, "api/v3/user/krl", false},
		{"with config", &krlCommand{config: &config.SystemConfig{CertificateAuthorityURL: "https://ssh.example.com"}}, "https://ssh.example.com/api/v3/user/krl", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.c.getKrlUrl()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getKrlUrl() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getKrlUrl() succeeded unexpectedly")
			}

			if got != tt.want {
				t.Errorf("getKrlUrl() = %v, want %v", got, tt.want)
			}
		})
	}
}
