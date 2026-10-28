// fenrir-release-sign signs Linux/macOS agent releases with the Ed25519 release key.
//
//	fenrir-release-sign -key release-ed25519.pem -public                       # print the public key to pin
//	fenrir-release-sign -key release-ed25519.pem -out dir -release N -version V -build-id B \
//	    linux:amd64:fenrir-agent-linux-amd64 macos:arm64:fenrir-agent-darwin-arm64 ...
//
// For each binary it writes <platform>-<arch>.manifest.json and <platform>-<arch>.manifest.sig into -out.
// The key can live off the server: run this on the machine that holds it, against the built binaries, and copy
// the manifest and signature files into the server's deploy/releases directory.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AntiVirus/agent/linux/pkg/fleet"
)

func main() {
	keyPath := flag.String("key", "", "Ed25519 private key (PKCS#8 PEM)")
	public := flag.Bool("public", false, "print the base64 public key and exit")
	out := flag.String("out", ".", "output directory")
	release := flag.Int64("release", 0, "release number (must increase with every release)")
	version := flag.String("version", "", "agent version")
	buildID := flag.String("build-id", "", "agent build id")
	channel := flag.String("channel", "stable", "release channel")
	days := flag.Int("expires-days", 180, "days until the manifest expires")
	flag.Parse()

	key, err := fleet.LoadReleaseSigningKey(*keyPath)
	if err != nil {
		fail("could not load the release key: %v", err)
	}
	if *public {
		fmt.Println(base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
		return
	}
	if *release <= 0 || flag.NArg() == 0 {
		fail("need -release and at least one platform:arch:path")
	}
	now := time.Now().UTC().Truncate(time.Second)
	for _, spec := range flag.Args() {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) != 3 {
			fail("bad binary spec %q (want platform:arch:path)", spec)
		}
		data, err := os.ReadFile(parts[2])
		if err != nil {
			fail("%v", err)
		}
		sum := sha256.Sum256(data)
		manifest, sig, err := fleet.SignRelease(key, fleet.ReleaseManifest{
			Platform: parts[0], Arch: parts[1], Channel: *channel, Release: *release, Version: *version, BuildID: *buildID,
			SHA256: hex.EncodeToString(sum[:]), Size: int64(len(data)), Issued: now, Expires: now.AddDate(0, 0, *days),
		})
		if err != nil {
			fail("%v", err)
		}
		base := filepath.Join(*out, parts[0]+"-"+parts[1]+".manifest")
		if err := os.WriteFile(base+".json", manifest, 0o644); err != nil {
			fail("%v", err)
		}
		if err := os.WriteFile(base+".sig", []byte(sig), 0o644); err != nil {
			fail("%v", err)
		}
	}
}

func fail(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "fenrir-release-sign: "+format+"\n", args...)
	os.Exit(1)
}
