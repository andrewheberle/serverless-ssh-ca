package host

import (
	"testing"
)

func Test_certPath(t *testing.T) {
	tests := []struct {
		name    string
		keypath string
		want    string
	}{
		{"rsa", "/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_rsa_key-cert.pub"},
		{"ecdsa", "/etc/ssh/ssh_host_ecdsa_key", "/etc/ssh/ssh_host_ecdsa_key-cert.pub"},
		{"ed25519", "/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_ed25519_key-cert.pub"},
		{"ed25519", "/some/other/path/ssh_host_ed25519_key", "/some/other/path/ssh_host_ed25519_key-cert.pub"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := certPath(tt.keypath)
			if got != tt.want {
				t.Errorf("certPath() = %v, want %v", got, tt.want)
			}
		})
	}
}
