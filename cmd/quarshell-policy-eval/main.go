package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-policy"
	"gopkg.in/yaml.v3"
)

type vector struct {
	Policy     string                     `yaml:"policy"`
	Filesystem []policy.FilesystemRequest `yaml:"filesystem"`
	Network    []policy.NetworkRequest    `yaml:"network"`
	Process    []policy.ProcessRequest    `yaml:"process"`
}

type output struct {
	Filesystem []policy.Decision `json:"filesystem,omitempty"`
	Network    []policy.Decision `json:"network,omitempty"`
	Process    []policy.Decision `json:"process,omitempty"`
	Error      string            `json:"error,omitempty"`
	ErrorCode  string            `json:"error_code,omitempty"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: quarshell-policy-eval <vector.yaml>")
		os.Exit(2)
	}
	body, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read vector")
		os.Exit(2)
	}
	var input vector
	if err := yaml.Unmarshal(body, &input); err != nil {
		write(output{Error: "invalid vector", ErrorCode: "invalid"})
		os.Exit(1)
	}
	document, err := policy.Parse(strings.NewReader(input.Policy), policy.DefaultLimits())
	if err != nil {
		write(output{Error: domain.SafeMessage(err), ErrorCode: string(domain.CodeOf(err))})
		os.Exit(1)
	}
	snapshot, err := document.Snapshot(1, time.Now())
	if err != nil {
		write(output{Error: domain.SafeMessage(err), ErrorCode: string(domain.CodeOf(err))})
		os.Exit(1)
	}
	result := output{}
	for _, request := range input.Filesystem {
		result.Filesystem = append(result.Filesystem, snapshot.EvaluateFilesystem(request))
	}
	for _, request := range input.Network {
		result.Network = append(result.Network, snapshot.EvaluateNetwork(request))
	}
	for _, request := range input.Process {
		result.Process = append(result.Process, snapshot.EvaluateProcess(request))
	}
	write(result)
}

func write(value output) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}
