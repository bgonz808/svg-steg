//go:build !js

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage("")
	}
	cmd := os.Args[1]
	var err error
	switch cmd {
	case "encode":
		err = cmdEncode(os.Args[2:])
	case "decode":
		err = cmdDecode(os.Args[2:])
	case "capacity":
		err = cmdCapacity(os.Args[2:])
	case "diff":
		err = cmdDiff(os.Args[2:])
	case "self-test", "selftest":
		err = cmdSelfTest(os.Args[2:])
	case "help", "--help", "-h":
		if cmd == "help" && len(os.Args) >= 3 {
			printCommandHelp(os.Args[2])
			return
		}
		usage("")
	default:
		usage("unknown subcommand: " + cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
