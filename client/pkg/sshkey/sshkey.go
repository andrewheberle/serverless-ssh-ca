// The sshkey provides a simple way to generate a 256-bit ECDSA private key
// for SSH.
package sshkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// GenerateKey will generate an OpenSSH ECDSA private key using
// the P-256 elliptic curve.
//
// The resulting key is returned as a byte slice in OpenSSH PEM
// format.
func GenerateKey(comment string) ([]byte, error) {
	// generate ECDSA key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// encode to openssh format
	privKey, err := ssh.MarshalPrivateKey(key, comment)
	if err != nil {
		return nil, err
	}

	pemBytes := pem.EncodeToMemory(privKey)
	if pemBytes == nil {
		return nil, fmt.Errorf("could not encode key")
	}

	return pemBytes, nil
}

// ParseKey will parse the provided byte slice (in OpenSSH ECDSA Private Key format)
// and return an [*ecdsa.PrivateKey].
//
// Any parsing errors will result in a nil [*ecdsa.PrivateKey] returned along
// with the error.
//
// Only ECDSA format private keys are supported by this function.
func ParseKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	privateKey, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse private key file: %w", err)
	}

	ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an ECDSA key; its type is %T", privateKey)
	}

	return ecdsaKey, nil
}
