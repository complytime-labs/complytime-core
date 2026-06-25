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

func CheckFlags(name string) {
	v := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *v {
		fmt.Printf("%s %s (commit: %s)\n", name, Version, Commit)
		os.Exit(0)
	}
}
