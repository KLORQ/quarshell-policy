package policy_test

import (
	"testing"

	"github.com/KLORQ/quarshell-policy/corepolicy"
)

func TestPathValidationUsesSegments(t *testing.T) {
	for _, valid := range []string{"/workspace/file..bak", "/opt/tool..new"} {
		doc := policy.Document{Version: 1, FilesystemPolicy: &policy.FilesystemPolicy{ReadOnly: []string{valid}}, Binaries: []string{valid}}
		if err := doc.Validate(); err != nil {
			t.Fatalf("valid path %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"relative/path", "/workspace/../secret", "/workspace/./file"} {
		doc := policy.Document{Version: 1, FilesystemPolicy: &policy.FilesystemPolicy{ReadOnly: []string{invalid}}}
		if err := doc.Validate(); err == nil {
			t.Fatalf("invalid filesystem path %q accepted", invalid)
		}
		doc.FilesystemPolicy = nil
		doc.Binaries = []string{invalid}
		if err := doc.Validate(); err == nil {
			t.Fatalf("invalid binary path %q accepted", invalid)
		}
	}
}
