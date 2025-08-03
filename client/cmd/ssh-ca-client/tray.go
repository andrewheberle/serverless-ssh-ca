//go:build tray

//go:generate go-winres make --product-version=git-tag --file-version=git-tag

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/cmd"
)

func logFatal(format string, a ...any) {
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}

	out, err := os.OpenFile(filepath.Join(home, cmd.ConfigDirName, "error.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		panic(err)
	}
	defer out.Close()

	fmt.Fprintf(out, format, a...)
	os.Exit(1)
}
