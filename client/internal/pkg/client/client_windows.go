package client

import (
	"context"

	"github.com/ndbeals/winssh-pageant/pageant"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// RunPageantProxy will proxy PuTTY Agent connections to the native OpenSSH
// SSH Agent.
//
// This will block until the provided context is complete or
// [*LoginHandler.ShutdownPageantProxy()] is run.
func (lh *LoginHandler) RunPageantProxy(ctx context.Context) error {
	if !lh.pageantProxy {
		return ErrPageantProxyNotEnabled
	}

	// start as a goroutine
	go func() {
		p := pageant.NewDefaultHandler(`\\.\pipe\openssh-ssh-agent`, true)
		p.Run()
	}()

	// block here until context is finished or ShutdownPageantProxy is run
	select {
	case <-lh.pageantProxyDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// addedKey returns the SSH key to be added to the Agent
func addedKey(key interface{}, cert *ssh.Certificate) agent.AddedKey {
	return agent.AddedKey{
		PrivateKey:  key,
		Certificate: cert,
		Comment:     cert.KeyId,
	}
}
