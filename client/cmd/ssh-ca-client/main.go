package main

import (
	"context"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/cmd"
)

func main() {
	if err := cmd.Execute(context.Background(), os.Args[1:]); err != nil {
		logFatal("Error during execution: %s\n", err)
	}
}
