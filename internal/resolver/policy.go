package resolver

import (
	"fmt"
	"sort"

	"github.com/opsbento/remediation-core/internal/findings"
)

type Registry interface {
	Versions(packageName string) ([]string, error)
}

type Policy struct {
	AllowMajor bool
}

func ResolveMinimumSafe(group findings.Group, registry Registry, policy Policy) (string, error) {
	available, err := registry.Versions(group.PackageName)
	if err != nil {
		return "", err
	}
	availableSet := map[string]bool{}
	for _, version := range available {
		if !IsPrerelease(version) {
			availableSet[version] = true
		}
	}

	current, err := ParseVersion(group.InstalledVersion)
	if err != nil {
		return "", err
	}

	candidates := map[string]bool{}
	for _, finding := range group.Findings {
		if len(finding.FixedVersions) == 0 {
			return "", fmt.Errorf("finding %s has no known fixed version", finding.VulnerabilityID)
		}
		for _, fixed := range finding.FixedVersions {
			if !availableSet[fixed] || IsPrerelease(fixed) || Compare(fixed, group.InstalledVersion) <= 0 {
				continue
			}
			target, err := ParseVersion(fixed)
			if err != nil {
				continue
			}
			if !policy.AllowMajor && target.Major != current.Major {
				continue
			}
			candidates[fixed] = true
		}
	}

	var sorted []string
	for candidate := range candidates {
		if fixesAll(candidate, group.Findings) {
			sorted = append(sorted, candidate)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return Compare(sorted[i], sorted[j]) < 0
	})
	if len(sorted) == 0 {
		return "", fmt.Errorf("no safe version satisfies policy")
	}
	return sorted[0], nil
}

func fixesAll(candidate string, fs []findings.Finding) bool {
	for _, finding := range fs {
		ok := false
		for _, fixed := range finding.FixedVersions {
			if Compare(candidate, fixed) >= 0 {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
