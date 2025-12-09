package protect

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os/user"

	"github.com/zalando/go-keyring"
)

// Decrypt will decrypt provided data using the secret reference in "name"
// using the Secret Service API via D-Bus
func Decrypt(data []byte, name string) ([]byte, error) {
	key, err := getOrCreateKey(name)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt data: %w", err)
	}

	return decrypt(key, data)
}

// Encrypt will encrypt provided data using the secret reference in "name"
// using the Secret Service API via D-Bus
func Encrypt(data []byte, name string) ([]byte, error) {
	key, err := getOrCreateKey(name)
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

func getOrCreateKey(name string) ([]byte, error) {
	// get user details
	u, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("error looking up user %w", err)
	}

	// attempt to get secret from keyring
	secret, err := keyring.Get(name, u.Username)
	if errors.Is(err, keyring.ErrNotFound) {
		// not found so generate and save
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("error generating key: %w", err)
		}

		// encode key to base64 string
		secret = base64.StdEncoding.EncodeToString(key)

		// set secret in keyring
		if err := keyring.Set(name, u.Username, secret); err != nil {
			return nil, fmt.Errorf("error saving base64 key to keyring: %w", err)
		}

		// return generated key once saved
		return key, nil
	}

	// decode returned base64 secret
	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("error decoding base64 key: %w", err)
	}

	return key, nil
}

func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return aesGCM.Open(nil, nonce, ciphertext, nil)
}

func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}
