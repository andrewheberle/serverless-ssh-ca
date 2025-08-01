package sshkey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

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
