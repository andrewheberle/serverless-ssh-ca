package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/cli"
)

func main() {
	if err := cli.Execute(context.Background(), os.Args[1:]); err != nil {
		slog.Error("error during execution", "error", err)
		os.Exit(1)
	}
}
