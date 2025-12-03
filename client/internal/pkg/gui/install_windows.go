package gui

import "golang.org/x/sys/windows/svc/eventlog"

func runInstall() error {
	return eventlog.InstallAsEventCreate("Serverless SSH CA Client", eventlog.Error|eventlog.Warning|eventlog.Info)
}

func runUninstall() error {
	return eventlog.Remove("Serverless SSH CA Client")
}
