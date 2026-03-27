//go:build snap

package version

import "runtime/debug"

// Version returns the version set via ldflags or debug.BuildInfo
func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}

	return info.Main.Version
}
