//go:build !windows && !linux

package protect

func NewDefaultProtector() Protector {
	return &PlainProtector{}
}
