package cli

import (
	"bytes"
	"os"
	"testing"
)

func Test_showversion(t *testing.T) {
	defer func() { stdout = os.Stdout }()

	tests := []struct {
		name    string // description of this test case
		n       string
		asjson  bool
		want    []byte
		wantErr bool
	}{
		{"as text", "ssh-ca-client-cli", false, []byte("ssh-ca-client-cli devel\n"), false},
		{"as json", "ssh-ca-client-cli", true, []byte("{\"name\":\"ssh-ca-client-cli\",\"version\":\"devel\"}\n"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := new(bytes.Buffer)
			stdout = buf
			gotErr := showversion(tt.n, tt.asjson)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("showversion() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("showversion() succeeded unexpectedly")
			}

			got := buf.Bytes()
			if !bytes.Equal(tt.want, got) {
				t.Errorf("showversion() = %s, want %s", got, tt.want)
			}
		})
	}
}
