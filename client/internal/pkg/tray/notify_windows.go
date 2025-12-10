package tray

import "github.com/gen2brain/beeep"

func (app *Application) prerun() {
	// set app name in beeep
	beeep.AppName = app.title
}

// Sends a desktop notification
func (app *Application) notify(title string, message string, icon string) {
	// grab icon
	b := app.getIcon(icon)

	// set notification
	if err := beeep.Notify(title, message, b); err != nil {
		app.logger.Error("could not send notification", "error", err)
	}
}
