package sidecar

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

var errMissingResolverURL = errors.New("--resolver-url is required")

// RunServe parses the CLI arguments, constructs the sidecar runtime, and runs
// the HTTP server until the context is canceled or the server exits.
func RunServe(ctx context.Context, args []string) error {
	config, err := parseServeConfig(args)
	if err != nil {
		return err
	}
	server, err := NewServer(config)
	if err != nil {
		return err
	}
	return server.Run(ctx)
}

// parseServeConfig converts the small sidecar flag surface into the runtime
// config used by the server package.
func parseServeConfig(args []string) (Config, error) {
	flags := flag.NewFlagSet("isomer-go", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	config := Config{}
	flags.StringVar(&config.Host, "host", "127.0.0.1", "HTTP host")
	flags.IntVar(&config.Port, "port", 8788, "HTTP port")
	flags.StringVar(&config.ResolverURL, "resolver-url", "", "did:webs resolver base URL")
	flags.StringVar(&config.ResourceRoot, "resource-root", ".", "w3c-crosswalk repository root")

	if err := flags.Parse(args); err != nil {
		return Config{}, fmt.Errorf("parse flags: %w", err)
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}
