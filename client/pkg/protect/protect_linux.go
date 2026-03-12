package protect

func NewDefaultProtector() Protector {
	return &KeyringProtector{}
}
