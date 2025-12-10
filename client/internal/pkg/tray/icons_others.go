//go:build linux

package tray

func trayIconFiles() map[string]string {
	return map[string]string{
		"ok":      "icons/ok.png",
		"error":   "icons/error.png",
		"warning": "icons/warning.png",
	}
}
