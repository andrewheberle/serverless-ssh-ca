package krl_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/api"
	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/krl"
	"golang.org/x/crypto/ssh"
)

var (
	emptykrl []byte = []byte{
		83, 83, 72, 75, 82, 76, 10, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
		0, 0, 0, 105, 212, 134, 192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0,
	}
	singleitemkrl []byte = []byte{
		83, 83, 72, 75, 82, 76, 10, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
		0, 0, 0, 105, 212, 150, 233, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 1, 0, 0, 0, 125, 0, 0, 0, 104, 0, 0, 0, 19, 101, 99, 100, 115,
		97, 45, 115, 104, 97, 50, 45, 110, 105, 115, 116, 112, 50, 53, 54, 0,
		0, 0, 8, 110, 105, 115, 116, 112, 50, 53, 54, 0, 0, 0, 65, 4, 235, 135,
		144, 107, 178, 77, 169, 17, 143, 229, 212, 117, 47, 246, 32, 122, 223,
		122, 172, 184, 252, 223, 27, 21, 91, 101, 72, 187, 45, 114, 162, 180,
		155, 154, 226, 254, 38, 100, 74, 110, 65, 240, 134, 93, 173, 153, 96,
		155, 72, 32, 53, 230, 250, 109, 216, 116, 185, 27, 1, 128, 68, 149,
		103, 18, 0, 0, 0, 0, 32, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 1,
	}
)

const (
	capublickey       string = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOuHkGuyTakRj+XUdS/2IHrfeqy4/N8bFVtlSLstcqK0m5ri/iZkSm5B8IZdrZlgm0ggNeb6bdh0uRsBgESVZxI="
	altcapublickey    string = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMVtQh5Agnm9nknP29cudULJc2Fdp0ok65tui/+GJ8x/"
	emptykrlSignature string = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
EE64eQa7JNqRGP5dR1L/Yget96rLj83xsVW2VIuy1yorSbmuL+JmRKbkHwhl2tmWCbSCA1
5vpt2HS5GwGARJVnEgAAAC5rcmxAY29tLmdpdGh1Yi5zZXJ2ZXJsZXNzLXNzaC1jYS5hbm
RyZXdoZWJlcmxlAAAAAAAAAAZzaGE1MTIAAABlAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYA
AABKAAAAIQCba5YCLPYh37+I8I6HuTTIwECXfvjWDcWnja5hEnAq6wAAACEAhuWuJ6CejS
+CctiQacwVcK8B1Ge1HIZsqUcA05XmLTo=
-----END SSH SIGNATURE-----`
	singleitemkrlSignature string = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAE
EE64eQa7JNqRGP5dR1L/Yget96rLj83xsVW2VIuy1yorSbmuL+JmRKbkHwhl2tmWCbSCA1
5vpt2HS5GwGARJVnEgAAAC5rcmxAY29tLmdpdGh1Yi5zZXJ2ZXJsZXNzLXNzaC1jYS5hbm
RyZXdoZWJlcmxlAAAAAAAAAAZzaGE1MTIAAABkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYA
AABJAAAAIC8Ym6ZW5kQQscBqKf4zaWfAUg75ApEzHMNHmUaiZPaiAAAAIQDUF0vXlOXnhQ
XVEZqGFoKDQf2bUJaTX2mSodUrjNrQvg==
-----END SSH SIGNATURE-----`
)

type mockClient struct {
	krl []byte
	sig string
}

func (c *mockClient) Do(req *http.Request) (*http.Response, error) {
	if req.URL.String() != "https://ssh.example.com/api/v3/host/krl" {
		return &http.Response{
			StatusCode: http.StatusNotFound,
			Header: http.Header{
				"Content-Type": []string{"text/plain"},
			},
			Body: &mockBody{r: bytes.NewReader(make([]byte, 0))},
		}, nil
	}

	b, err := json.Marshal(api.KeyRevocationListResponse{
		Krl:       c.krl,
		Signature: c.sig,
	})
	if err != nil {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Header: http.Header{
				"Content-Type": []string{"text/plain"},
			},
			Body: &mockBody{r: bytes.NewReader(make([]byte, 0))},
		}, nil

	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: &mockBody{r: bytes.NewReader(b)},
	}, nil
}

type mockBody struct {
	r *bytes.Reader
}

func (b *mockBody) Read(p []byte) (n int, err error) {
	return b.r.Read(p)
}

func (b *mockBody) Close() error {
	return nil
}

func TestGetAndVerify(t *testing.T) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(capublickey))
	if err != nil {
		panic(err)
	}

	altpub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(altcapublickey))
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name          string
		krldata       []byte
		signature     string
		want          *krl.Response
		wantErr       bool
		pub           ssh.PublicKey
		strict        bool
		wantVerifyErr bool
	}{
		{"invalid data", []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, "", &krl.Response{Krl: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}, Signature: ""}, false, nil, false, true},
		{"empty krl", emptykrl, "", &krl.Response{Krl: emptykrl, Signature: ""}, false, nil, false, false},
		{"krl with one serial", singleitemkrl, "", &krl.Response{Krl: singleitemkrl, Signature: ""}, false, nil, false, false},
		{"empty krl (strict no signature)", emptykrl, "", &krl.Response{Krl: emptykrl, Signature: ""}, false, nil, true, true},
		{"krl with one serial (strict no signature)", singleitemkrl, "", &krl.Response{Krl: singleitemkrl, Signature: ""}, false, nil, true, true},
		{"empty krl (strict with signature)", emptykrl, emptykrlSignature, &krl.Response{Krl: emptykrl, Signature: emptykrlSignature}, false, pub, true, false},
		{"krl with one serial (strict with signature)", singleitemkrl, singleitemkrlSignature, &krl.Response{Krl: singleitemkrl, Signature: singleitemkrlSignature}, false, pub, true, false},
		{"krl with one serial (strict with signature and alt ca)", singleitemkrl, singleitemkrlSignature, &krl.Response{Krl: singleitemkrl, Signature: singleitemkrlSignature}, false, altpub, true, true},
		{"krl with one serial (strict with invalid signature)", singleitemkrl, emptykrlSignature, &krl.Response{Krl: singleitemkrl, Signature: emptykrlSignature}, false, pub, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := krl.Get("https://ssh.example.com/", "host", api.WithHTTPClient(&mockClient{krl: tt.krldata, sig: tt.signature}))
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Read() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Read() succeeded unexpectedly")
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Read() = %v, want %v", got, tt.want)
			}

			if tt.strict {
				if gotVerifyErr := got.VerifyStrict(tt.pub); gotVerifyErr != nil {
					if !tt.wantVerifyErr {
						t.Errorf("VerifyStrict() failed: %v", gotVerifyErr)
					}
					return
				}
				if tt.wantVerifyErr {
					t.Fatal("VerifyStrict() succeeded unexpectedly")
				}
			} else {
				if gotVerifyErr := got.Verify(tt.pub); gotVerifyErr != nil {
					if !tt.wantVerifyErr {
						t.Errorf("Verify() failed: %v", gotVerifyErr)
					}
					return
				}
				if tt.wantVerifyErr {
					t.Fatal("Verify() succeeded unexpectedly")
				}
			}

		})
	}
}
