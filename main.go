package main

import (
	"flag"
	"fmt"
	"github.com/pblind/crypto"
	"os"
)

func main() {
	println("pblind")

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "pblind v0.0.1\n\n")
		_, _ = fmt.Fprintf(os.Stderr, "Usage:\n\tpblind -client -state [statedir] -version 2 -transports [transport1,transport2,...]\n\n")
		_, _ = fmt.Fprintf(os.Stderr, "Example:\n\tpblind -client -state state -version 2 -transports obfs2\n\n")
		_, _ = fmt.Fprintf(os.Stderr, "Flags:\n\n")
		flag.PrintDefaults()
	}

	genkeys := flag.Bool("genkeys", false, "Generate signing keys")

	flag.Parse()

	if *genkeys {
		println("Generating keys...")

	}
}
