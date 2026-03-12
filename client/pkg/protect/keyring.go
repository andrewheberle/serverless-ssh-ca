package protect

import (
	"fmt"
)

type KeyringProtector struct {
    key []byte
}

func NewKeyringProtector() (*KeyringProtector, error) {
    return &KeyringProtector{}, nil
}

// Decrypt will decrypt provided data using the secret reference in "name"
// using the Secret Service API via D-Bus
func (p *KeyringProtector) Decrypt(data []byte, name string) ([]byte, error) {
	if p.key == nil {
        key, err := getOrCreateKey(name, true)
	    if err != nil {
		    return nil, fmt.Errorf("could not decrypt data: %w", err)
        }
        p.key = key
	}
	
	return decrypt(p.key, data)
}

// Encrypt will encrypt provided data using the secret reference in "name"
// using the Secret Service API via D-Bus
func (p *KeyringProtector) Encrypt(data []byte, name string) ([]byte, error) {
	if p.key == nil {
        key, err := getOrCreateKey(name, true)
	    if err != nil {
		    return nil, fmt.Errorf("could not decrypt data: %w", err)
        }
        p.key = key
	}
    
    return encrypt(p.key, data)
}
