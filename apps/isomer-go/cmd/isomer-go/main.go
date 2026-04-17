// Package main is the process entrypoint for the isomer-go sidecar.
//
// The real CLI contract lives in the internal sidecar serve runner. This file
// stays intentionally small so process startup and signal handling remain easy
// to audit.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"isomer-go/internal/sidecar"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := sidecar.RunServe(ctx, os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}
