package protect

import (
	"bytes"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestKeyringProtector_MockedEncryptDecrypt(t *testing.T) {
	keyring.MockInit()
	tests := []struct {
		name       string
		data       []byte
		secretname string
	}{
		{"data should match", []byte("somedata"), "secret"},
	}
    p := &KeyringProtector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := p.Encrypt(tt.data, tt.secretname)
			if err != nil {
				t.Fatalf("Encrypt() failed: %v", err)
			}

			if bytes.Equal(tt.data, ciphertext) {
				t.Fatalf("Encrypt() error: data was unchanged")
			}

			plaintext, err := p.Decrypt(ciphertext, tt.secretname)
			if err != nil {
				t.Fatalf("Encrypt() failed: %v", err)
			}

			if !bytes.Equal(tt.data, plaintext) {
				t.Errorf("Decrypt() = %v, want %v", plaintext, tt.data)
			}
		})
	}
}

func TestKeyringProtector_MockedDecrypt(t *testing.T) {
	keyring.MockInit()
	tests := []struct {
		name    string
		data    []byte
		want    []byte
		wantErr bool
	}{
		{"expected to fail as no key exists", []byte("here is some content"), nil, true},
	}
    p := &KeyringProtector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := p.Decrypt(tt.data, tt.name)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Decrypt() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Decrypt() succeeded unexpectedly")
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}
