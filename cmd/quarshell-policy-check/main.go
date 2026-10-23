package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-policy"
)

type result struct {
	Accepted  bool   `json:"accepted"`
	Version   uint32 `json:"version,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
	Error     string `json:"error,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: quarshell-policy-check <file>")
		os.Exit(2)
	}
	file, err := os.Open(os.Args[1])
	if err != nil {
		write(result{Accepted: false, ErrorCode: "io", Error: "cannot open input"})
		os.Exit(2)
	}
	defer file.Close()
	document, err := policy.Parse(file, policy.DefaultLimits())
	if err != nil {
		write(result{Accepted: false, ErrorCode: string(domain.CodeOf(err)), Error: domain.SafeMessage(err)})
		os.Exit(1)
	}
	if _, err := document.Typed(); err != nil {
		write(result{Accepted: false, ErrorCode: string(domain.CodeOf(err)), Error: domain.SafeMessage(err)})
		os.Exit(1)
	}
	version, _ := document.Version()
	write(result{Accepted: true, Version: version})
}

func write(value result) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}
