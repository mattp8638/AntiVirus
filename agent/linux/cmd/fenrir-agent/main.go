// fenrir-agent is the managed Linux endpoint agent for Fenrir Cloud.
//
//	FENRIR_SERVER=https://cloud.example FENRIR_ENROLLMENT_TOKEN=fet_... fenrir-agent
//
// It needs no kernel modules or eBPF; run it as root for full coverage
// (all processes, quarantine anywhere, nftables isolation).
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/AntiVirus/agent/linux/pkg/fleet"
	"github.com/AntiVirus/agent/linux/pkg/remote"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	// macOS: the agent starts itself as the screen helper inside the signed-in user's session.
	if len(os.Args) == 2 && os.Args[1] == remote.HelperCommand {
		if err := remote.RunDesktopHelper(); err != nil {
			log.Printf("desktop helper: %v", err)
			os.Exit(1)
		}
		return
	}
	server := flag.String("server", env("FENRIR_SERVER", ""), "Fenrir Cloud URL")
	token := flag.String("token", env("FENRIR_ENROLLMENT_TOKEN", ""), "enrollment token (first run only)")
	stateDir := flag.String("state-dir", env("FENRIR_STATE_DIR", "/var/lib/fenrir"), "where identity, quarantine and spool live")
	dryRun := flag.Bool("dry-run-isolation", os.Getenv("FENRIR_DRY_RUN_ISOLATION") == "1", "record isolation without changing the firewall")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *version {
		println(fleet.Version)
		return
	}
	if *server == "" {
		log.Fatal("set FENRIR_SERVER or --server")
	}
	agent := fleet.New(fleet.Config{Server: *server, EnrollmentToken: *token, StateDir: *stateDir, DryRunIsolation: *dryRun})
	if err := agent.Start(); err != nil {
		log.Fatal(err)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		log.Println("stopping; flushing telemetry")
		agent.Stop()
	}()
	log.Printf("Fenrir agent %s running against %s", fleet.Version, *server)
	agent.Run()
}
