package policy

import "testing"

func TestProcessIdentityMatchesCompatValues(t *testing.T) {
	for _, value := range []string{"sandbox", "1", "1000", "4294967294"} {
		if err := validateProcessIdentity("run_as_user", value); err != nil {
			t.Errorf("valid identity %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"0", "root", "nobody", "4294967295", "4294967296", "-1", "1.0"} {
		if err := validateProcessIdentity("run_as_user", value); err == nil {
			t.Errorf("invalid identity %q accepted", value)
		}
	}
}
