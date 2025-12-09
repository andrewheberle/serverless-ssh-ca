//go:build !windows && !linux

package protect

// Decrypt returns the data as-is on this platform
func Decrypt(data []byte, name string) ([]byte, error) {
	return data, nil
}

// Encrypt returns the data as-is on this platform
func Encrypt(data []byte, name string) ([]byte, error) {
	return data, nil
}

// Decrypt returns the data as-is on this platform
func (p *DefaultProtector) Decrypt(data []byte, name string) ([]byte, error) {
	return Decrypt(data, name)
}

// Encrypt returns the data as-is on this platform
func (p *DefaultProtector) Encrypt(data []byte, name string) ([]byte, error) {
	return Encrypt(data, name)
}
