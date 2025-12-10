//go:build linux

package tray

func (app *Application) prerun() {
}

// This currently does nothing as "github.com/gen2brain/beeep.Notify" causes
// the entire GUI to panic on Linux
func (app *Application) notify(title string, message string, icon string) {
	app.logger.Info("notifications are disabled on this platform", "title", title, "message", message, "icon", icon)
}
