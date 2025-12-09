package config

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/protect"
)

type mockProtector struct {
}

func (p *mockProtector) Encrypt(data []byte, name string) ([]byte, error) {
	return data, nil
}

func (p *mockProtector) Decrypt(data []byte, name string) ([]byte, error) {
	return data, nil
}

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name    string
		system  string
		user    string
		want    *Config
		wantErr bool
	}{
		{"missing", "missing.yml", "missing.yml", nil, true},
		{"system missing", "missing.yml", "testdata/validuser.yml", nil, true},
		{"user missing", "testdata/validsystem.yml", "missing.yml",
			&Config{
				systemConfigName: "testdata/validsystem.yml",
				system: SystemConfig{
					Issuer:                  "OIDC Issuer",
					ClientID:                "OIDC Client ID",
					Scopes:                  []string{"openid", "email", "profile"},
					RedirectURL:             "http://localhost:3000/auth/callback",
					CertificateAuthorityURL: "https://ssh-ca.example.com/",
				},
				userConfigName: "missing.yml",
				user:           UserConfig{},
				protector:      protect.NewDefaultProtector(),
			}, false},
		{"invalid system", "testdata/invalidsystem.yml", "testdata/validuser.yml", nil, true},
		{"invalid user", "testdata/validsystem.yml", "testdata/invaliduser.yml", nil, true},
		{"both valid", "testdata/validsystem.yml", "testdata/validuser.yml",
			&Config{
				systemConfigName: "testdata/validsystem.yml",
				system: SystemConfig{
					Issuer:                  "OIDC Issuer",
					ClientID:                "OIDC Client ID",
					Scopes:                  []string{"openid", "email", "profile"},
					RedirectURL:             "http://localhost:3000/auth/callback",
					CertificateAuthorityURL: "https://ssh-ca.example.com/",
				},
				userConfigName: "testdata/validuser.yml",
				user: UserConfig{
					PrivateKey: []byte("somedataencodedasbase64"),
				},
				protector: protect.NewDefaultProtector(),
			}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := LoadConfig(tt.system, tt.user)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("LoadConfig() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("LoadConfig() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Oidc(t *testing.T) {
	tests := []struct {
		name   string
		system string
		user   string
		want   ClientOIDCConfig
	}{
		{"valid config", "testdata/validsystem.yml", "testdata/validuser.yml", ClientOIDCConfig{
			Issuer:      "OIDC Issuer",
			ClientID:    "OIDC Client ID",
			Scopes:      []string{"openid", "email", "profile"},
			RedirectURL: "http://localhost:3000/auth/callback",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := LoadConfig(tt.system, tt.user)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			got := c.Oidc()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Oidc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_CertificateAuthorityURL(t *testing.T) {
	tests := []struct {
		name   string
		system string
		user   string
		want   string
	}{
		{"valid config", "testdata/validsystem.yml", "testdata/validuser.yml", "https://ssh-ca.example.com/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := LoadConfig(tt.system, tt.user)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			got := c.CertificateAuthorityURL()
			if got != tt.want {
				t.Errorf("CertificateAuthorityURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_getPrivateKeyBytes(t *testing.T) {
	tests := []struct {
		name    string
		system  string
		user    string
		want    []byte
		wantErr bool
	}{
		{"valid config", "testdata/validsystem.yml", "testdata/validuser.yml", []byte("somedataencodedasbase64"), false},
		{"no key", "testdata/validsystem.yml", "missing.yml", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := LoadConfig(tt.system, tt.user)
			if err != nil {
				t.Fatalf("could not construct receiver type: %v", err)
			}
			// use mockProtector for test
			c.protector = &mockProtector{}
			got, gotErr := c.getPrivateKeyBytes()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getPrivateKeyBytes() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getPrivateKeyBytes() succeeded unexpectedly")
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("getPrivateKeyBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}
