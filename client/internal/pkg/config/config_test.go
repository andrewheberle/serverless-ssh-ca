package config

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/protect"
	"github.com/andrewheberle/serverless-ssh-ca/client/pkg/sshkey"
	"golang.org/x/crypto/ssh"
)

var _ protect.Protector = &mockProtector{}

type mockProtector struct {
}

func (p *mockProtector) Encrypt(data []byte, name string) ([]byte, error) {
	return bytes.Clone(data), nil
}

func (p *mockProtector) Decrypt(data []byte, name string) ([]byte, error) {
	return bytes.Clone(data), nil
}

var _ Persistence = &mockPersistence{}

type mockPersistence struct {
	data UserConfig
}

func (p *mockPersistence) Save(c UserConfig) error {
	p.data = c
	return nil
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
				system: SystemConfig{
					Issuer:                  "OIDC Issuer",
					ClientID:                "OIDC Client ID",
					Scopes:                  []string{"openid", "email", "profile"},
					RedirectURL:             "http://localhost:3000/auth/callback",
					CertificateAuthorityURL: "https://ssh-ca.example.com/",
				},
				user:        UserConfig{},
				persistence: &YamlPersistence{name: "missing.yml"},
				protector:   protect.NewDefaultProtector(),
			}, false},
		{"invalid system", "testdata/invalidsystem.yml", "testdata/validuser.yml", nil, true},
		{"invalid user", "testdata/validsystem.yml", "testdata/invaliduser.yml", nil, true},
		{"both valid", "testdata/validsystem.yml", "testdata/validuser.yml",
			&Config{
				system: SystemConfig{
					Issuer:                  "OIDC Issuer",
					ClientID:                "OIDC Client ID",
					Scopes:                  []string{"openid", "email", "profile"},
					RedirectURL:             "http://localhost:3000/auth/callback",
					CertificateAuthorityURL: "https://ssh-ca.example.com/",
				},
				user: UserConfig{
					PrivateKey: []byte("somedataencodedasbase64"),
				},
				persistence: &YamlPersistence{name: "testdata/validuser.yml"},
				protector:   protect.NewDefaultProtector(),
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

func TestLoadUserConfigOnly(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    *Config
		wantErr bool
	}{
		{"missing", "missing.yml", &Config{
			user:        UserConfig{},
			persistence: &YamlPersistence{name: "missing.yml"},
			protector:   protect.NewDefaultProtector(),
		}, false},
		{"valid config", "testdata/validuser.yml",
			&Config{
				user: UserConfig{
					PrivateKey: []byte("somedataencodedasbase64"),
				},
				persistence: &YamlPersistence{name: "testdata/validuser.yml"},
				protector:   protect.NewDefaultProtector(),
			}, false},
		{"invalid config", "testdata/invaliduser.yml", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := LoadUserConfigOnly(tt.config)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("LoadUserConfigOnly() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("LoadUserConfigOnly() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LoadUserConfigOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Oidc(t *testing.T) {
	// minimal test config
	testconfig := &Config{
		system: SystemConfig{
			Issuer:      "OIDC Issuer",
			ClientID:    "OIDC Client ID",
			Scopes:      []string{"openid", "email", "profile"},
			RedirectURL: "http://localhost:3000/auth/callback",
		},
	}

	tests := []struct {
		name   string
		config *Config
		want   ClientOIDCConfig
	}{
		{"valid config", testconfig, ClientOIDCConfig{
			Issuer:      "OIDC Issuer",
			ClientID:    "OIDC Client ID",
			Scopes:      []string{"openid", "email", "profile"},
			RedirectURL: "http://localhost:3000/auth/callback",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.Oidc()
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Oidc() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_CertificateAuthorityURL(t *testing.T) {
	// minimal test config
	testconfig := &Config{
		system: SystemConfig{
			CertificateAuthorityURL: "https://ssh-ca.example.com/",
		},
	}

	tests := []struct {
		name   string
		config *Config
		want   string
	}{
		{"valid config", testconfig, "https://ssh-ca.example.com/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.CertificateAuthorityURL()
			if got != tt.want {
				t.Errorf("CertificateAuthorityURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_getPrivateKeyBytes(t *testing.T) {
	// minimal test config
	testconfig := &Config{
		user: UserConfig{
			PrivateKey: []byte("somedata"),
		},
		protector: &mockProtector{},
	}

	tests := []struct {
		name    string
		config  *Config
		want    []byte
		wantErr bool
	}{
		{"valid config", testconfig, []byte("somedata"), false},
		{"no key", &Config{
			user: UserConfig{
				PrivateKey: nil,
			},
		}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.config.getPrivateKeyBytes()
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

func TestConfig_GetRefreshToken(t *testing.T) {
	// minimal test config
	testconfig := &Config{
		user: UserConfig{
			RefreshToken: []byte("somedata"),
		},
		protector: &mockProtector{},
	}

	tests := []struct {
		name    string
		config  *Config
		want    string
		wantErr bool
	}{
		{"valid config", testconfig, "somedata", false},
		{"missing token", &Config{
			user: UserConfig{
				PrivateKey: nil,
			},
		}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.config.GetRefreshToken()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("GetRefreshToken() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("GetRefreshToken() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("GetRefreshToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_HasPrivateKey(t *testing.T) {
	// generate test key
	key, err := sshkey.GenerateKey("testkey")
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{"no key", &Config{}, false},
		{"invalid key", &Config{
			user: UserConfig{
				PrivateKey: []byte("somedatathatisntavalidprivatekey"),
			},
			protector: &mockProtector{},
		}, false},
		{"valid key", &Config{
			user: UserConfig{
				PrivateKey: key,
			},
			protector: &mockProtector{},
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.HasPrivateKey()
			if got != tt.want {
				t.Errorf("HasPrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_getPublicKeyBytes(t *testing.T) {
	// generate test key
	pemBytes, err := sshkey.GenerateKey("testkey")
	if err != nil {
		panic(err)
	}

	// parse into a private key
	key, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		panic(err)
	}

	// convert to public key
	publicBytes := ssh.MarshalAuthorizedKey(key.PublicKey())

	tests := []struct {
		name    string
		config  *Config
		want    []byte
		wantErr bool
	}{
		{"no key", &Config{}, nil, true},
		{"invalid key", &Config{
			user: UserConfig{
				PrivateKey: []byte("somedatathatisntavalidprivatekey"),
			},
			protector: &mockProtector{},
		}, nil, true},
		{"valid key", &Config{
			user: UserConfig{
				PrivateKey: pemBytes,
			},
			protector: &mockProtector{},
		}, publicBytes, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.config.getPublicKeyBytes()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getPublicKeyBytes() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getPublicKeyBytes() succeeded unexpectedly")
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("getPublicKeyBytes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_SetAndGetPrivateKeyBytes(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		pemBytes []byte
		wantErr  bool
	}{
		{"mock save", &Config{
			persistence: &mockPersistence{},
			protector:   &mockProtector{},
		}, []byte("somebytes"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotErr := tt.config.SetPrivateKeyBytes(tt.pemBytes)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("SetPrivateKeyBytes() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("SetPrivateKeyBytes() succeeded unexpectedly")
			}

			saved := tt.config.persistence.(*mockPersistence).data.PrivateKey
			if !bytes.Equal(saved, tt.config.user.PrivateKey) {
				t.Fatalf("SetPrivateKeyBytes() did not save: %v, want %v", saved, tt.config.user.PrivateKey)
			}

			got, gotErr := tt.config.GetPrivateKeyBytes()
			if gotErr != nil {
				t.Fatal("GetPrivateKeyBytes() failed")
			}
			if !bytes.Equal(got, tt.config.user.PrivateKey) {
				t.Errorf("GetPrivateKeyBytes() = %v, want %v", got, tt.config.user.PrivateKey)
			}
		})
	}
}

func TestConfig_HasCertificate(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{"no certificate", &Config{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.HasCertificate()
			if got != tt.want {
				t.Errorf("HasCertificate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_CertificateValid(t *testing.T) {
	tests := []struct {
		name   string
		config *Config
		want   bool
	}{
		{"no certificate", &Config{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.CertificateValid()
			if got != tt.want {
				t.Errorf("CertificateValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
