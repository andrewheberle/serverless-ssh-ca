//go:build aix || darwin || dragonfly || freebsd || (js && wasm) || linux || nacl || netbsd || openbsd || solaris

package protect

import "log/slog"

func Decrypt(data []byte, name string) ([]byte, error) {
	return data, nil
}

func Encrypt(data []byte, name string) ([]byte, error) {
	slog.Warn("this sensitive data has been saved unencrypted on this platform")
	return data, nil
}
