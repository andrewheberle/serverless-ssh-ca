package version

// verson should be set via ldflags
var version = "unset"

// Version returns the version set via ldflags or devel if unset
func Version() string {
	if version != "unset" {
		return version
	}

	return "devel"
}
