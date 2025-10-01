// The sshkey provides a simple way to generate a 256-bit ECDSA private key
// for SSH.
package sshkey

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

var (
	ErrUnsupportedKey = errors.New("unsupported key type")
)

const (
	DsaKey     = "dsa"
	RsaKey     = "rsa"
	EcdsaKey   = "ecdsa"
	Ed25519Key = "ed25519"
)

// GenerateKey will generate an OpenSSH ECDSA private key using
// the P-256 elliptic curve.
//
// The resulting key is returned as a byte slice in OpenSSH PEM
// format.
func GenerateKey(comment string) ([]byte, error) {
	return Generate(comment, EcdsaKey)
}

// ParseKey will parse the provided byte slice (in OpenSSH ECDSA Private Key format)
// and return an [*ecdsa.PrivateKey].
//
// Any parsing errors will result in a nil [*ecdsa.PrivateKey] returned along
// with the error.
//
// Only ECDSA format private keys are supported by this function.
func ParseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	privateKey, err := Parse(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key file: %w", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ECDSA key; its type is %T", privateKey)
	}

	return ecdsaKey, nil
}

// Generate will generate an OpenSSH private key using
// the specified format ("rsa", "dsa", "ecdsa" or "ed25519").
//
// The resulting key is returned as a byte slice in OpenSSH PEM
// format.
func Generate(comment, keytype string) ([]byte, error) {
	var key crypto.PrivateKey
	switch keytype {
	case RsaKey:
		var err error

		// generate RSA key
		key, err = rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, err
		}
	case DsaKey:
		var k *dsa.PrivateKey

		// generate DSA key
		if err := dsa.GenerateKey(k, rand.Reader); err != nil {
			return nil, err
		}

		key = k
	case EcdsaKey:
		var err error

		// generate ECDSA key
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
	case Ed25519Key:
		var err error

		// generate ed25519 key
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ErrUnsupportedKey
	}

	// encode to openssh format
	privKey, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, err
	}

	// conver to PEM
	pemBytes := pem.EncodeToMemory(privKey)
	if pemBytes == nil {
		return nil, fmt.Errorf("could not encode key")
	}

	return pemBytes, nil
}

// Parse will parse the provided byte slice (in OpenSSH Private Key format)
// and return RSA, DSA, ECDSA, or Ed25519 private key.
//
// The returned key must be cast to the correct type before use
func Parse(pemBytes []byte) (any, error) {
	privateKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	switch key := privateKey.(type) {
	case *rsa.PrivateKey, *dsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
		return key, nil
	}

	return nil, ErrUnsupportedKey
}

func IsRSA(key any) bool {
	_, ok := key.(*rsa.PrivateKey)

	return ok
}

func IsDSA(key any) bool {
	_, ok := key.(*dsa.PrivateKey)

	return ok
}

func IsECDSA(key any) bool {
	_, ok := key.(*ecdsa.PrivateKey)

	return ok
}

func IsEd25519(key any) bool {
	_, ok := key.(ed25519.PrivateKey)

	return ok
}
