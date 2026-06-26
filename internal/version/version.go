// SPDX-License-Identifier: Apache-2.0

package version

import (
	"flag"
	"fmt"
	"os"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

type Info struct {
	Name        string
	Description string
	EnvHelp     string
}

func CheckFlags(info Info) {
	v := flag.Bool("version", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s — %s\n\n", info.Name, info.Description)
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [flags]\n\nFlags:\n", info.Name)
		flag.PrintDefaults()
		if info.EnvHelp != "" {
			fmt.Fprint(os.Stderr, info.EnvHelp)
		}
	}
	flag.Parse()
	if *v {
		fmt.Printf("%s %s (commit: %s)\n", info.Name, Version, Commit)
		os.Exit(0)
	}
}
