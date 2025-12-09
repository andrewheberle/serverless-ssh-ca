package protect

import (
	"golang.zx2c4.com/wireguard/windows/conf/dpapi"
)

// Decrypt will decrypt the secret called "name" using the Windows DPAPI
func Decrypt(data []byte, name string) ([]byte, error) {
	return dpapi.Decrypt(data, name)
}

// Encrypt will encrypt the secret called "name" using the Windows DPAPI
func Encrypt(data []byte, name string) ([]byte, error) {
	return dpapi.Encrypt(data, name)
}

// Decrypt will decrypt the secret called "name" using the Windows DPAPI
func (p *DefaultProtector) Decrypt(data []byte, name string) ([]byte, error) {
	return Decrypt(data, name)
}

// Encrypt will encrypt the secret called "name" using the Windows DPAPI
func (p *DefaultProtector) Encrypt(data []byte, name string) ([]byte, error) {
	return Encrypt(data, name)
}
