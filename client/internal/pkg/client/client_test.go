package client

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func Test_GenerateUserAgent(t *testing.T) {
	tests := []struct {
		name    string
		appName string
		want    string
	}{
		{"basic", UserAgent, fmt.Sprintf("%s/%s (%s-%s)", UserAgent, "(devel)", runtime.GOOS, runtime.GOARCH)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateUserAgent(tt.appName)
			if tt.want != got {
				t.Errorf("GenerateUserAgent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_GenerateNonce(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		panic(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		panic(err)
	}

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	ecdsaSigner, err := ssh.NewSignerFromKey(ecdsaKey)
	if err != nil {
		panic(err)
	}

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	ed25519Signer, err := ssh.NewSignerFromKey(ed25519Key)
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name    string
		signer  ssh.Signer
		wantErr bool
	}{
		{"rsa", rsaSigner, false},
		{"ecdsa", ecdsaSigner, false},
		{"ed25519", ed25519Signer, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := GenerateNonce(tt.signer)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GenerateNonce() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("GenerateNonce() succeeded unexpectedly")
			}

			// no verification, just make sure it looks right
			parts := strings.Split(got, ".")
			if len(parts) != 3 {
				t.Fatalf("GenerateNonce() generated wrong number of parts: %v", len(parts))
			}

			// check timestamp seems ok
			ms, err := strconv.Atoi(parts[0])
			if err != nil {
				t.Fatalf("GenerateNonce() timestamp was not an integer: %v", err)
			}
			ts := time.Unix(int64(ms/1000), int64((ms%1000)*1000000))
			if ts.After(time.Now()) {
				t.Fatalf("GenerateNonce() timestamp was in the future: %v", ts)
			}

			// check signature format is expected
			sig := strings.Split(parts[2], ":")
			if len(sig) != 2 {
				t.Fatalf("GenerateNonce() generated wrong number of parts for signature: %v", len(sig))
			}
			format := sig[0]
			validFormats := []string{"ecdsa-sha2-nistp256", "ssh-ed25519", "ssh-rsa"}
			if !slices.Contains(validFormats, format) {
				t.Fatalf("GenerateNonce() signature did not include supported format: %v", format)
			}

		})
	}
}
