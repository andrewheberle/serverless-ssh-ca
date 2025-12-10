//go:build !windows

package client

import (
	"context"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var ErrPlatformNotSupported = errors.New("not supported on this platform")

// RunPageantProxy is not supported on this platform
func (lh *LoginHandler) RunPageantProxy(ctx context.Context) error {
	return ErrPlatformNotSupported
}

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
