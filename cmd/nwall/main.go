// Command nwall 是单一二进制的入口，按子命令分发。
package main

import (
	"fmt"
	"os"

	"github.com/mora1n/nwall/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "nwall:", err)
		os.Exit(1)
	}
}
