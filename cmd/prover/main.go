// Command quarshell-prover validates a policy and reports risk findings.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/KLORQ/quarshell-policy"
	"github.com/KLORQ/quarshell-policy/prover"
)

const version = "0.0.0-dev"

func main() {
	policyPath := flag.String("policy", "", "policy YAML file")
	jsonOutput := flag.Bool("json", false, "emit JSON")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()
	if *showVersion {
		fmt.Println("quarshell-prover", version)
		return
	}
	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "usage: quarshell-prover --policy FILE [--json]")
		os.Exit(2)
	}
	source, err := os.ReadFile(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "quarshell-prover:", err)
		os.Exit(1)
	}
	document, err := policy.Parse(bytes.NewReader(source), policy.DefaultLimits())
	if err != nil {
		fmt.Fprintln(os.Stderr, "quarshell-prover:", err)
		os.Exit(1)
	}
	typed, err := document.Typed()
	if err != nil {
		fmt.Fprintln(os.Stderr, "quarshell-prover:", err)
		os.Exit(1)
	}
	report := prover.Analyze(typed)
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(report)
	} else {
		fmt.Printf("risk score: %d\n", report.Score)
		for _, finding := range report.Findings {
			fmt.Printf("- [%s] %s: %s\n", finding.Severity, finding.Code, finding.Detail)
		}
	}
	if report.Score >= 80 {
		os.Exit(1)
	}
}
