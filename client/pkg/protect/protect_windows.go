package protect

import (
	"golang.zx2c4.com/wireguard/windows/conf/dpapi"
)

func Decrypt(data []byte, name string) ([]byte, error) {
	return dpapi.Decrypt(data, name)
}

func Encrypt(data []byte, name string) ([]byte, error) {
	return dpapi.Encrypt(data, name)
}
