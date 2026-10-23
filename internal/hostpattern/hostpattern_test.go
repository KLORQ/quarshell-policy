package hostpattern

import "testing"

func TestMatchCaseInsensitiveAndWildcards(t *testing.T) {
	cases := []struct {
		pattern, host string
		want          bool
	}{
		{"*.Example.COM", "API.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "deep.api.example.com", false},
		{"**.example.com", "deep.api.example.com", true},
		{"*-api.example.com", "tenant-api.example.com", true},
		{"*", "deep.api.example.com", false},
		{"**.example.com", "api.example.com", true},
		{"**.example.com", "example.com", false},
		{"api.**.com", "api.x.y.com", true},
		{"api.**.com", "api.com", false},
		{"**", "deep.api.example.com", true},
		{"**", "localhost", true},
		{"**", "", false},
		{"**", "api..example.com", false},
	}
	for _, tc := range cases {
		got, err := MatchString(tc.pattern, tc.host)
		if err != nil {
			t.Fatalf("MatchString(%q,%q): %v", tc.pattern, tc.host, err)
		}
		if got != tc.want {
			t.Errorf("MatchString(%q,%q)=%v want %v", tc.pattern, tc.host, got, tc.want)
		}
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	bad := []string{
		"",
		"api .example.com",
		"*.{prod,staging}.example.com",
		"api**.example.com",
		"api..example.com",
	}
	for _, p := range bad {
		if _, err := Parse(p); err == nil {
			t.Errorf("Parse(%q) expected error", p)
		}
	}
}

func TestPatternOverlapAndSelectorExclusions(t *testing.T) {
	parse := func(value string) Pattern {
		t.Helper()
		pattern, err := Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		return pattern
	}
	for _, tc := range []struct {
		left, right string
		want        bool
	}{
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "deep.api.example.com", false},
		{"**.example.com", "deep.api.example.com", true},
		{"*.example.com", "*.other.com", false},
	} {
		if got := parse(tc.left).Overlaps(parse(tc.right)); got != tc.want {
			t.Errorf("Overlaps(%q, %q)=%v, want %v", tc.left, tc.right, got, tc.want)
		}
	}
	include := []Pattern{parse("*.example.com")}
	if SelectorMayMatchPattern(include, []Pattern{parse("api.example.com")}, parse("api.example.com")) {
		t.Fatal("selector should exclude a concrete TLS-skip host")
	}
	if !SelectorMayMatchPattern(include, nil, parse("*.example.com")) {
		t.Fatal("selector should overlap wildcard candidate")
	}
}
