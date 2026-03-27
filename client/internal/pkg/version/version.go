//go:build !snap

package version

// verson is set via ldflags
var version = "devel"

// Version returns the version set via ldflags or debug.BuildInfo
func Version() string {
	return version
}
