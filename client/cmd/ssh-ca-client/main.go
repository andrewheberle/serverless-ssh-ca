//go:generate go-winres make --product-version=git-tag --file-version=git-tag

package main

import (
	"context"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/gui"
)

func main() {
	if err := gui.Execute(context.Background(), os.Args[1:]); err != nil {
		logFatal("Error during execution: %s\n", err)
	}
}
