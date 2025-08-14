//go:build tray

//go:generate go-winres make --product-version=git-tag --file-version=git-tag

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/svc/eventlog"
)

func logFatal(format string, a ...any) {
	logger, err := eventlog.Open("Serverless SSH CA Client")
	if err != nil {
		panic(err)
	}
	defer logger.Close()

	if err := logger.Error(1000, fmt.Sprintf(format, a...)); err != nil {
		panic(err)
	}

	os.Exit(1)
}
