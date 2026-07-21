package resolver

import (
	"testing"

	"github.com/opsbento/remediation-core/internal/findings"
)

type fakeRegistry []string

func (f fakeRegistry) Versions(string) ([]string, error) {
	return []string(f), nil
}

func TestResolveMinimumSafeSelectsVersionFixingAllFindings(t *testing.T) {
	group := findings.Group{
		PackageName:      "lodash",
		InstalledVersion: "4.17.19",
		Findings: []findings.Finding{
			{VulnerabilityID: "CVE-A", FixedVersions: []string{"4.17.20"}},
			{VulnerabilityID: "CVE-B", FixedVersions: []string{"4.17.21"}},
		},
	}

	got, err := ResolveMinimumSafe(group, fakeRegistry{"4.17.20", "4.17.21", "5.0.0"}, Policy{})
	if err != nil {
		t.Fatal(err)
	}
	if got != "4.17.21" {
		t.Fatalf("got %q, want 4.17.21", got)
	}
}

func TestResolveMinimumSafeBlocksMajorByDefault(t *testing.T) {
	group := findings.Group{
		PackageName:      "pkg",
		InstalledVersion: "1.2.3",
		Findings: []findings.Finding{
			{VulnerabilityID: "CVE-A", FixedVersions: []string{"2.0.0"}},
		},
	}

	if _, err := ResolveMinimumSafe(group, fakeRegistry{"2.0.0"}, Policy{}); err == nil {
		t.Fatal("expected major update to be blocked")
	}
}
