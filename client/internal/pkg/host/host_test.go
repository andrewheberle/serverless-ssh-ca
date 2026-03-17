package host

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
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

func TestLoginHandler_renewalRequired(t *testing.T) {
	now := time.Now()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	tests := []struct {
		name string // description of this test case
		lh   *LoginHandler
		cert sshKey
		want bool
	}{
		{"life left", &LoginHandler{renewat: 0.50, now: now, logger: logger}, sshKey{cert: &ssh.Certificate{ValidAfter: uint64(now.Unix()), ValidBefore: uint64(now.Add(time.Second * 120).Unix())}}, false},
		{"close to renweal", &LoginHandler{renewat: 0.50, now: now, logger: logger}, sshKey{cert: &ssh.Certificate{ValidAfter: uint64(now.Add(time.Second * -59).Unix()), ValidBefore: uint64(now.Add(time.Second * 61).Unix())}}, false},
		{"equal (should renew)", &LoginHandler{renewat: 0.50, now: now, logger: logger}, sshKey{cert: &ssh.Certificate{ValidAfter: uint64(now.Add(time.Second * -60).Unix()), ValidBefore: uint64(now.Add(time.Second * 60).Unix())}}, true},
		{"just ready to renew", &LoginHandler{renewat: 0.50, now: now, logger: logger}, sshKey{cert: &ssh.Certificate{ValidAfter: uint64(now.Add(time.Second * -61).Unix()), ValidBefore: uint64(now.Add(time.Second * 59).Unix())}}, true},
		{"no life left", &LoginHandler{renewat: 0.50, now: now, logger: logger}, sshKey{cert: &ssh.Certificate{ValidAfter: uint64(now.Add(time.Second * -120).Unix()), ValidBefore: uint64(now.Unix())}}, true},
		{"forced renewal", &LoginHandler{renewat: 1, now: now, logger: logger}, sshKey{cert: &ssh.Certificate{ValidAfter: uint64(now.Unix()), ValidBefore: uint64(now.Add(time.Second * 120).Unix())}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.lh.renewalRequired(tt.cert)
			if got != tt.want {
				t.Errorf("renewalRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}
