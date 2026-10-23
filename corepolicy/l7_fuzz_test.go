package policy

import (
	"regexp"
	"strings"
	"testing"
)

func TestRecursiveGlobRequiresFullSuffix(t *testing.T) {
	if MatchL7Path("/admin/**/users", "/admin/x/users/extra") {
		t.Fatal("recursive glob matched a path beyond its suffix")
	}
	if !MatchL7Path("/admin/**/users", "/admin/x/users") {
		t.Fatal("recursive glob missed its full suffix")
	}
}

func FuzzMatchPathGlob(f *testing.F) {
	for _, sample := range [][2]string{
		{"/admin/**/users", "/admin/x/users/extra"},
		{"/admin/**/users", "/admin/x/users"},
		{"/a/*/c", "/a/b/c"},
		{"/**", "/anything/here"},
	} {
		f.Add(sample[0], sample[1])
	}
	f.Fuzz(func(t *testing.T, pattern, value string) {
		if len(pattern) > 64 || len(value) > 64 || strings.Trim(pattern, "/abc*?") != "" || strings.Trim(value, "/abc") != "" {
			return
		}
		var expression strings.Builder
		expression.WriteByte('^')
		for i := 0; i < len(pattern); i++ {
			switch pattern[i] {
			case '*':
				if i+1 < len(pattern) && pattern[i+1] == '*' {
					expression.WriteString(".*")
					i++
				} else {
					expression.WriteString("[^/]*")
				}
			case '?':
				expression.WriteString("[^/]")
			default:
				expression.WriteByte(pattern[i])
			}
		}
		expression.WriteByte('$')
		want := regexp.MustCompile(expression.String()).MatchString(value)
		if got := matchPathGlob(pattern, value); got != want {
			t.Fatalf("pattern %q value %q: got %v want %v", pattern, value, got, want)
		}
	})
}
