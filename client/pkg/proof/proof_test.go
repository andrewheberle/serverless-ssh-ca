package proof

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

func TestGenerate(t *testing.T) {
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

	// set known timestamp for testing by overriding getTimestamp function
	now := time.Now()

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
		// set getTimestamp to return our known timestamp for testing so its not affected by changes later in the test
		getTimestamp = func() int64 {
			return now.UnixMilli()
		}

		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := Generate(tt.signer)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Generate() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Generate() succeeded unexpectedly")
			}

			// no verification, just make sure it looks right
			parts := strings.Split(got.String(), ".")
			if len(parts) != 3 {
				t.Fatalf("Generate() generated wrong number of parts: %v", len(parts))
			}

			// check timestamp seems ok
			ms, err := strconv.Atoi(parts[0])
			if err != nil {
				t.Fatalf("Generate() timestamp was not an integer: %v", err)
			}
			ts := time.Unix(int64(ms/1000), int64((ms%1000)*1000000))
			if ts.UnixMilli() != now.UnixMilli() {
				t.Fatalf("Generate() timestamp did not match expected: %v", ts)
			}

			// check signature format is expected and can be parsed back manually
			signature, err := base64.StdEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatalf("Generate() signature was not base64: %v", err)
			}
			sig, err := sshsig.Unarmor(signature)
			if err != nil {
				t.Fatalf("Generate() could not dearmor signature: %v", err)
			}
			if err := sshsig.Verify(
				bytes.NewReader([]byte(fmt.Sprintf("%s.%s", parts[0], parts[1]))),
				sig,
				tt.signer.PublicKey(),
				sshsig.HashSHA512,
				Namespace,
			); err != nil {
				t.Fatalf("Generate() signature did not verify: %v", err)
			}

			// check it can be verfied
			if err := got.Verify(tt.signer.PublicKey(), 5*time.Minute); err != nil {
				t.Fatalf("Proof.Verify() failed: %v", err)
			}

			// check it fails if we change getTimestamp to be far in the past
			getTimestamp = func() int64 {
				return now.Add(-10 * time.Minute).UnixMilli()
			}
			if err := got.Verify(tt.signer.PublicKey(), 5*time.Minute); err == nil {
				t.Fatal("Proof.Verify() succeeded unexpectedly with old timestamp")
			}

			// check it fails if we change getTimestamp to be far in the future
			getTimestamp = func() int64 {
				return now.Add(10 * time.Minute).UnixMilli()
			}
			if err := got.Verify(tt.signer.PublicKey(), 5*time.Minute); err == nil {
				t.Fatal("Proof.Verify() succeeded unexpectedly with future timestamp")
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		proof   string
		want    Proof
		wantErr bool
	}{
		{"invalid format", "not-a-valid-proof", Proof{}, true},
		{"invalid timestamp", "not-a-timestamp.fingerprint.signature", Proof{}, true},
		{"invalid signature encoding", "12345.fingerprint.not-base64", Proof{}, true},
		{"invalid signature format", "12345.fingerprint." + base64.StdEncoding.EncodeToString([]byte("not-a-valid-signature")), Proof{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := Parse(tt.proof)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Parse() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Parse() succeeded unexpectedly")
			}
			// This tests error conditions so should never be equal
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %v, want %v", got, tt.want)
			}
		})
	}
}
