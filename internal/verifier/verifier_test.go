package verifier

import "testing"

func TestGuardAllowedAcceptsDependencyFiles(t *testing.T) {
	err := GuardAllowed([]string{"package.json", "package-lock.json"}, []string{"package.json", "package-lock.json"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGuardAllowedRejectsUnexpectedFile(t *testing.T) {
	err := GuardAllowed([]string{"package.json", "README.md"}, []string{"package.json", "package-lock.json"})
	if err == nil {
		t.Fatal("expected unexpected file error")
	}
}
