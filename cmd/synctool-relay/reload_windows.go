//go:build windows

package main

import (
	"log"

	"github.com/yellowdking/synctool/internal/relay"
)

func watchCertReload(_ *relay.CertManager, _ *log.Logger) func() {
	return func() {}
}
