//go:build !windows

package main

import (
	"fmt"
	"os"
)

func logFatal(format string, a ...any) {
	fmt.Printf(format, a...)
	os.Exit(1)
}
