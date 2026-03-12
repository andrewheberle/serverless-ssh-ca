package protect

func NewDefaultProtector() Protector {
	return &DpapiProtector{}
}
