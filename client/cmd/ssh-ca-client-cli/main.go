package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/client/internal/pkg/cli"
)

func main() {
	h := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{})
	logger := slog.New(h)

	if err := cli.Execute(context.Background(), os.Args[1:]); err != nil {
		logger.Error("error during execution", "error", err)
		os.Exit(1)
	}
}
