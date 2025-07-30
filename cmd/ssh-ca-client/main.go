package main

import (
	"context"
	"fmt"
	"os"

	"github.com/andrewheberle/serverless-ssh-ca/internal/pkg/cmd"
)

func main() {
	if err := cmd.Execute(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error during execution: %s\n", err)
		os.Exit(1)
	}
}
