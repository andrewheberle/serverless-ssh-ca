//go:build !tray

package main

import (
	"fmt"
	"os"
)

func logFatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}
