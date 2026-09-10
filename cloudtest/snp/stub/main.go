// Command stub is a diagnostic ./app for the SNP loader: it intentionally does
// nothing but stay alive and print a heartbeat. Bundling it (TOKENHIVE_BUILD_-
// STUB=1) lets a test separate "does the confidential instance even boot under
// the two-tier loader" from "does the real tee application exit". If a stub
// image stays running, boot + ratchet + enforcement are fine and the tee app
// itself is what terminates; if it also stops, the boot chain is the culprit.
package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	i := 0
	for {
		time.Sleep(10 * time.Second)
		fmt.Fprintf(os.Stdout, "STUB_ALIVE pid=%d tick=%d\n", os.Getpid(), i)
		i++
	}
}