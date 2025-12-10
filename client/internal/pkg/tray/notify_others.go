//go:build linux

package tray

import (
	"bytes"
	"image"
	"image/draw"
	"image/png"
	"io"
	"log"
	"time"

	"github.com/esiqveland/notify"
	"github.com/godbus/dbus/v5"
)

func (app *Application) prerun() {
}

// Sends a desktop notification
//
// This is identical to beeep.Notify except the dbus session bus connection is
// not closed after sending the notification to avoid crashing the GUI.
func (app *Application) notify(title string, message string, icon string) {
	conn, err := dbus.SessionBus()
	if err != nil {
		app.logger.Error("could not send notification",
			"title", title,
			"message", message,
			"error", err,
		)
		return
	}

	n := notify.Notification{
		AppName:       app.title,
		AppIcon:       "",
		Summary:       title,
		Body:          message,
		ExpireTimeout: time.Second * 5,
	}

	n.Hints = map[string]dbus.Variant{}
	n.SetUrgency(notify.UrgencyNormal)

	iconData, ok := app.notificationIcons[icon]
	if !ok {
		iconData = app.notificationIcons[defaultIcon]
	}

	rgba, err := bytesToRGBA(iconData)
	if err == nil {
		imageHint := notify.HintImageDataRGBA(rgba)
		n.Hints[imageHint.ID] = imageHint.Variant
	}

	notifier, err := notify.New(conn,
		notify.WithLogger(log.New(io.Discard, "", log.Flags())),
	)
	if err != nil {
		app.logger.Error("could not send notification",
			"title", title,
			"message", message,
			"error", err,
		)
		return
	}
	defer notifier.Close()

	_, err = notifier.SendNotification(n)
	if err != nil {
		app.logger.Error("could not send notification",
			"title", title,
			"message", message,
			"error", err,
		)
		return
	}
}

func bytesToRGBA(data []byte) (*image.RGBA, error) {
	i, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	if img, ok := i.(*image.RGBA); ok {
		return img, nil
	}

	b := i.Bounds()
	img := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(img, img.Bounds(), i, b.Min, draw.Src)

	return img, nil
}
