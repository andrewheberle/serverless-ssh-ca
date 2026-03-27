//go:build !snap

package version

// verson is set via ldflags
var version = "devel"

func Version() string {
	return version
}
