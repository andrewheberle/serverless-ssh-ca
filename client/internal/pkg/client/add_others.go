//go:build !windows

package client

import (
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// addedKey returns the SSH key to be added to the Agent
// On non-Windows platforms this includes LifetimeSecs that aligns with
// the certificate expiry time
func addedKey(key interface{}, cert *ssh.Certificate) agent.AddedKey {
	// work out lifetime
	expiry := time.Unix(int64(cert.ValidBefore), 0)
	lifetime := time.Until(expiry).Seconds()

	return agent.AddedKey{
		PrivateKey:   key,
		Certificate:  cert,
		Comment:      cert.KeyId,
		LifetimeSecs: uint32(lifetime),
	}
}
