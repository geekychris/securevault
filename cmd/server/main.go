package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"securevault/pkg/server"
)

func main() {
	configFile := flag.String("config", "config.yaml", "Path to configuration file")
	flag.Parse()

	config, err := server.LoadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	srv, err := server.NewServer(config)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	go func() {
		if err := srv.Start(); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	log.Printf("SecureVault server started on %s:%d", config.Server.Address, config.Server.Port)

	if srv.SealManager().IsInitialized() {
		if srv.SealManager().IsSealed() {
			log.Println("Vault is SEALED. Submit unseal keys via POST /v1/sys/unseal")
		} else {
			log.Println("Vault is UNSEALED and ready to accept requests")
		}
	} else {
		log.Println("Vault is NOT INITIALIZED. Initialize via POST /v1/sys/init")
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited properly")
}
