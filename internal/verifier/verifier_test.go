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

func TestPorcelainPath(t *testing.T) {
	tests := map[string]string{
		" M package-lock.json":                "package-lock.json",
		"M  package-lock.json":                "package-lock.json",
		"M package-lock.json":                 "package-lock.json",
		"?? package.json":                     "package.json",
		"R  old-package.json -> package.json": "package.json",
	}

	for input, want := range tests {
		if got := porcelainPath(input); got != want {
			t.Fatalf("porcelainPath(%q) = %q, want %q", input, got, want)
		}
	}
}
