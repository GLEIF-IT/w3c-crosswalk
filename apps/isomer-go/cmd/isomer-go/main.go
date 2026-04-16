package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"isomer-go/internal/sidecar"
)

func main() {
	host := flag.String("host", "127.0.0.1", "HTTP host")
	port := flag.Int("port", 8788, "HTTP port")
	resolverURL := flag.String("resolver-url", "", "did:webs resolver base URL")
	resourceRoot := flag.String("resource-root", ".", "w3c-crosswalk repository root")
	flag.Parse()

	if *resolverURL == "" {
		log.Fatal("--resolver-url is required")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server, err := sidecar.NewServer(sidecar.Config{
		Host:         *host,
		Port:         *port,
		ResolverURL:  *resolverURL,
		ResourceRoot: *resourceRoot,
	})
	if err != nil {
		log.Fatal(err)
	}
	if err = server.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
