package cli

import (
	"bytes"
	"net/http"
	"reflect"
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

type mockClient struct {
	*http.Client
	res []byte
}

func (m *mockClient) Get(url string) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       &mockBody{r: bytes.NewReader(m.res)},
	}, nil
}

type mockBody struct {
	r *bytes.Reader
}

func (m *mockBody) Read(p []byte) (n int, err error) {
	return m.r.Read(p)
}

func (m *mockBody) Close() error {
	return nil
}

func Test_krlCommand_getKrlPayload(t *testing.T) {
	tests := []struct {
		name    string
		c       *krlCommand
		want    *krlResponsePayload
		wantErr bool
	}{
		{"invalid response", &krlCommand{krlUrl: "https://ssh.example.com/api/v4/host/krl", client: &mockClient{res: []byte("invalid")}}, nil, true},
		{"empty response", &krlCommand{krlUrl: "https://ssh.example.com/api/v4/host/krl", client: &mockClient{res: make([]byte, 0)}}, nil, true},
		{"empty but valid json", &krlCommand{krlUrl: "https://ssh.example.com/api/v4/host/krl", client: &mockClient{res: []byte("{}")}}, &krlResponsePayload{}, false},
		{"has valid response",
			&krlCommand{
				krlUrl: "https://ssh.example.com/api/v4/host/krl",
				client: &mockClient{
					res: []byte("{\"krl\":\"dGhla3JsYXNiYXNlNjQ=\", \"signature\":\"sshsig\"}")}},
			&krlResponsePayload{
				KeyRevocationList: []byte("thekrlasbase64"),
				Signature:         "sshsig",
			}, false},
		{"has valid response with extra field",
			&krlCommand{
				krlUrl: "https://ssh.example.com/api/v4/host/krl",
				client: &mockClient{
					res: []byte("{\"krl\":\"dGhla3JsYXNiYXNlNjQ=\", \"signature\":\"sshsig\", \"extrafield\":\"shouldcauseerror\"}")}},
			nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := tt.c.getKrlPayload()
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("getKrlPayload() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("getKrlPayload() succeeded unexpectedly")
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getKrlPayload() = %v, want %v", got, tt.want)
			}
		})
	}
}
