package protect

import "bytes"

type PlainProtector struct {}

// Decrypt returns the data as-is on this platform
func (p *PlainProtector) Decrypt(data []byte, name string) ([]byte, error) {
	return bytes.Clone(data), nil
}

// Encrypt returns the data as-is on this platform
func (p *PlainProtector) Encrypt(data []byte, name string) ([]byte, error) {
	return bytes.Clone(data), nil
}
