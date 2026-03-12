package protect

import (
	"fmt"
)

// Decrypt will decrypt provided data using the secret reference in "name"
// using the Secret Service API via D-Bus
func Decrypt(data []byte, name string) ([]byte, error) {
	key, err := getOrCreateKey(name, false)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data: %w", err)
	}

	return decrypt(key, data)
}

// Encrypt will encrypt provided data using the secret reference in "name"
// using the Secret Service API via D-Bus
func Encrypt(data []byte, name string) ([]byte, error) {
	key, err := getOrCreateKey(name, true)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data: %w", err)
	}

	return encrypt(key, data)
}

// Decrypt will decrypt provided data using the secret reference in "name"
// using the Secret Service API via D-Bus
func (p *DefaultProtector) Decrypt(data []byte, name string) ([]byte, error) {
	return Decrypt(data, name)
}

// Encrypt will encrypt provided data using the secret reference in "name"
// using the Secret Service API via D-Bus
func (p *DefaultProtector) Encrypt(data []byte, name string) ([]byte, error) {
	return Encrypt(data, name)
}
