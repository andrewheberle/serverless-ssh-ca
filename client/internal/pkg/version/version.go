package version

import "runtime/debug"

// verson should be set via ldflags
var version = "unset"

// Version returns the version set via ldflags or debug.BuildInfo
func Version() string {
	if version != "unset" {
		return version
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	return info.Main.Version
}
