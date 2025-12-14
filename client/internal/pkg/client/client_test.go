package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
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
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
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

			// check signature format is expected and can be parsed back
			signature, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatalf("GenerateNonce() signature was not base64: %v", err)
			}
			sig, err := sshsig.Unarmor(signature)
			if err != nil {
				t.Fatalf("GenerateNonce() could not dearmor signature: %v", err)
			}
			if err := sshsig.Verify(
				bytes.NewReader([]byte(fmt.Sprintf("%s.%s", parts[0], parts[1]))),
				sig,
				tt.signer.PublicKey(),
				sshsig.HashSHA512,
				SignatureNamespace,
			); err != nil {
				t.Fatalf("GenerateNonce() signature did not verify: %v", err)
			}
		})
	}
}
