package client

import (
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// addedKey returns the SSH key to be added to the Agent
func addedKey(key interface{}, cert *ssh.Certificate) agent.AddedKey {
	return agent.AddedKey{
		PrivateKey:  key,
		Certificate: cert,
		Comment:     cert.KeyId,
	}
}
