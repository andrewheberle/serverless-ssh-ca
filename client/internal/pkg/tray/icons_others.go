//go:build !windows

package tray

func trayIcons() map[string]string {
	return map[string]string{
		"ok":      "icons/ok.png",
		"error":   "icons/error.png",
		"warning": "icons/warning.png",
	}
}
