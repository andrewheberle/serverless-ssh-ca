package protect

// Protector is the interface for enctypting or decrypting data
type Protector interface {
	Decrypt(data []byte, name string) ([]byte, error)
	Encrypt(data []byte, name string) ([]byte, error)
}

type DefaultProtector struct {
}

func NewDefaultProtector() *DefaultProtector {
	return &DefaultProtector{}
}
