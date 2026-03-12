package protect

import (
	"golang.zx2c4.com/wireguard/windows/conf/dpapi"
)

type DpapiProtector struct {}

// Decrypt will decrypt the secret called "name" using the Windows DPAPI
func (p *DpapiProtector) Decrypt(data []byte, name string) ([]byte, error) {
	return dpapi.Decrypt(data, name)
}

// Encrypt will encrypt the secret called "name" using the Windows DPAPI
func (p *DpapiProtector) Encrypt(data []byte, name string) ([]byte, error) {
	return dpapi.Encrypt(data, name)
}
