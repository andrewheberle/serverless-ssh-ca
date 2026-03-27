//go:build snap

package version

import "runtime/debug"

func Version() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "devel"
	}

	return info.Main.Version
}
