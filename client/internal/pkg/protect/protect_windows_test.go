package protect

import (
	"reflect"
	"testing"
)

func TestEncrypt(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		in       string
		out      string
		wantErr  bool
		wantSame bool
	}{
		{"same name", []byte("input"), "data", "data", false, true},
		{"different name", []byte("input"), "data", "other", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			protected, err := Encrypt(tt.data, tt.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			plain, _ := Decrypt(protected, tt.out)
			if !reflect.DeepEqual(plain, tt.data) && tt.wantSame {
				t.Errorf("Encrypt() = %v, Decrypt() = %v", plain, tt.data)
			}
		})
	}
}
