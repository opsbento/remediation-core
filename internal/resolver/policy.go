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

func ResolveUpgradeCandidates(packageName, installedVersion string, registry Registry, policy Policy) ([]string, error) {
	available, err := registry.Versions(packageName)
	if err != nil {
		return nil, err
	}
	current, err := ParseVersion(installedVersion)
	if err != nil {
		return nil, err
	}
	var candidates []string
	for _, candidate := range available {
		if IsPrerelease(candidate) || Compare(candidate, installedVersion) <= 0 {
			continue
		}
		target, err := ParseVersion(candidate)
		if err != nil {
			continue
		}
		if !policy.AllowMajor && target.Major != current.Major {
			continue
		}
		candidates = append(candidates, candidate)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return Compare(candidates[i], candidates[j]) < 0
	})
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no upgrade candidate satisfies policy")
	}
	return candidates, nil
}

func ResolveMinimumSafe(group findings.Group, registry Registry, policy Policy) (string, error) {
	candidates, err := ResolveCandidates(group, registry, policy)
	if err != nil {
		return "", err
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no safe version satisfies policy")
	}
	return candidates[0], nil
}

func ResolveCandidates(group findings.Group, registry Registry, policy Policy) ([]string, error) {
	available, err := registry.Versions(group.PackageName)
	if err != nil {
		return nil, err
	}
	availableSet := map[string]bool{}
	for _, version := range available {
		if !IsPrerelease(version) {
			availableSet[version] = true
		}
	}

	current, err := ParseVersion(group.InstalledVersion)
	if err != nil {
		return nil, err
	}

	for _, finding := range group.Findings {
		if len(finding.FixedVersions) == 0 {
			return nil, fmt.Errorf("finding %s has no known fixed version", finding.VulnerabilityID)
		}
	}

	var sorted []string
	for candidate := range availableSet {
		if Compare(candidate, group.InstalledVersion) <= 0 {
			continue
		}
		target, err := ParseVersion(candidate)
		if err != nil {
			continue
		}
		if !policy.AllowMajor && target.Major != current.Major {
			continue
		}
		if fixesAll(candidate, group.Findings) {
			sorted = append(sorted, candidate)
		}
	}
	sort.Slice(sorted, func(i, j int) bool {
		return Compare(sorted[i], sorted[j]) < 0
	})
	if len(sorted) == 0 {
		return nil, fmt.Errorf("no safe version satisfies policy")
	}
	return sorted, nil
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
