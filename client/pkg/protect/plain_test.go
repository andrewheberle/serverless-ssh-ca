package protect

import (
	"reflect"
	"testing"
)

func TestPlainProtector_Encrypt(t *testing.T) {
    p := &PlainProtector{}
    data := []byte{"somedata"}

    got, err := p.Encrypt(data, "secret")
    if err != nil {
        t.Errorf("Encrypt() failed unexpectedly: %v", err)
        return
    }
    if !reflect.DeepEqual(data, got) {
        t.Errorf("Encrypt() did not match. Got = %v, Want = %v", got, data)
    }
}

func TestPlainProtector_Decrypt(t *testing.T) {
    p := &PlainProtector{}
    data := []byte{"somedata"}

    got, err := p.Decrypt(data, "secret")
    if err != nil {
        t.Errorf("Decrypt() failed unexpectedly: %v", err)
        return
    }
    if !reflect.DeepEqual(data, got) {
        t.Errorf("Decrypt() did not match. Got = %v, Want = %v", got, data)
    }
}

