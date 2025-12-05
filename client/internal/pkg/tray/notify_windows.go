package tray

import "github.com/gen2brain/beeep"

const defaultIcon = "ok"

// Sends a desktop notification
func (app *Application) notify(title string, message string, icon string) {
	// grab icon
	b, ok := app.notificationIcons[icon]
	if !ok {
		b = app.notificationIcons[defaultIcon]
	}

	// set notification
	if err := beeep.Notify(title, message, b); err != nil {
		app.logger.Error("could not send notification", "error", err)
	}
}
