package sshcert

import (
	"crypto/ecdsa"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ParseCert will parse the provided byte slice (in OpenSSH certficate format)
// and return a [*ssh.Certificate].
//
// Any parsing errors will result in a nil [*ssh.Certificate] returned along
// with the error.
func ParseCert(certBytes []byte) (*ssh.Certificate, error) {
	// Parse the certificate.
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SSH public key/certificate: %w", err)
	}

	// Type assert to *ssh.Certificate. If it's not a certificate, this will fail.
	cert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("the provided key is not a SSH certificate, it is a %T", parsedKey)
	}

	return cert, nil
}

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
