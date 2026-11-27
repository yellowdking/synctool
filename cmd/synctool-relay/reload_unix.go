//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/yellowdking/synctool/internal/relay"
)

func watchCertReload(cm *relay.CertManager, logger *log.Logger) func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
				if err := cm.Reload(); err != nil {
					logger.Printf("WARN: SIGHUP certificate reload failed: %v", err)
				} else {
					logger.Printf("TLS certificate reloaded via SIGHUP")
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
