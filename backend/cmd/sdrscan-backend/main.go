// Command sdrscan-backend is the SDRScan backend: REST API, scan runner and
// ingest endpoint in one binary.
package main

import (
	"fmt"
	"os"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.1.0"

func main() {
	args := os.Args[1:]
	cmd := "serve"
	if len(args) > 0 && len(args[0]) > 0 && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "migrate":
		err = cmdMigrate(args)
	case "user":
		err = cmdUser(args)
	case "token":
		err = cmdToken(args)
	case "maintenance":
		err = cmdMaintenance(args)
	case "version", "--version":
		fmt.Println("sdrscan-backend", version)
		return
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `sdrscan-backend - SDRScan backend

Usage:
  sdrscan-backend serve                         run the HTTP server, workers and scheduler (default)
  sdrscan-backend migrate                       apply database migrations and exit
  sdrscan-backend user create|list|reset-password|set-role|enable|disable   manage accounts directly in the database
  sdrscan-backend token create --name <label> [--project-id <id>]            create an ingest token
  sdrscan-backend maintenance rebuild-state [--codebase-id <id>]             recompute is_current and summaries
  sdrscan-backend version

Configuration is read from environment variables (DATABASE_URL, SDRSCAN_*); see backend/README.md.
`)
}
