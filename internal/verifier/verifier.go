package verifier

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/opsbento/remediation-core/internal/ecosystems"
	"github.com/opsbento/remediation-core/internal/findings"
)

type Outcome struct {
	TargetFindingsRemoved bool
	NewCriticalFindings   int
	DependencyFilesValid  bool
	ChangedFiles          []string
}

func ChangedFiles(ctx context.Context, repoRoot string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "git", "status", "--porcelain", "--", ".")
	cmd.Dir = repoRoot
	raw, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		path := porcelainPath(line)
		if path == "" {
			continue
		}
		files = append(files, path)
	}
	return files, nil
}

func porcelainPath(line string) string {
	if strings.TrimSpace(line) == "" {
		return ""
	}

	var path string
	if len(line) >= 4 && line[2] == ' ' {
		path = strings.TrimSpace(line[3:])
	} else {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return ""
		}
		path = fields[1]
	}

	if _, newPath, ok := strings.Cut(path, " -> "); ok {
		path = newPath
	}
	return strings.TrimSpace(path)
}

func GuardAllowed(files []string, allowed []string) error {
	allowedSet := map[string]bool{}
	for _, file := range allowed {
		allowedSet[filepath.ToSlash(file)] = true
	}
	for _, file := range files {
		if !allowedSet[filepath.ToSlash(file)] {
			return fmt.Errorf("unexpected changed file %q", file)
		}
	}
	return nil
}

func HasDirectDependency(deps []ecosystems.Dependency, packageName string) (ecosystems.Dependency, bool) {
	for _, dep := range deps {
		if dep.Name == packageName && dep.Relationship == "direct" {
			return dep, true
		}
	}
	return ecosystems.Dependency{}, false
}

func TargetFindingsRemoved(after []findings.Finding, packageName string, vulnIDs []string) bool {
	targets := map[string]bool{}
	for _, id := range vulnIDs {
		targets[id] = true
	}
	for _, finding := range after {
		if finding.PackageName == packageName && targets[finding.VulnerabilityID] {
			return false
		}
	}
	return true
}

func NewCriticalFindings(before, after []findings.Finding) int {
	beforeSet := findingSet(before, "critical")
	count := 0
	for _, finding := range after {
		if !strings.EqualFold(finding.Severity, "critical") {
			continue
		}
		key := finding.PackageName + "\x00" + finding.InstalledVersion + "\x00" + finding.VulnerabilityID
		if !beforeSet[key] {
			count++
		}
	}
	return count
}

func findingSet(fs []findings.Finding, severity string) map[string]bool {
	out := map[string]bool{}
	for _, finding := range fs {
		if severity != "" && !strings.EqualFold(finding.Severity, severity) {
			continue
		}
		key := finding.PackageName + "\x00" + finding.InstalledVersion + "\x00" + finding.VulnerabilityID
		out[key] = true
	}
	return out
}

func GitAvailable(ctx context.Context, workdir string) bool {
	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--is-inside-work-tree")
	cmd.Dir = workdir
	var out bytes.Buffer
	cmd.Stdout = &out
	return cmd.Run() == nil && strings.TrimSpace(out.String()) == "true"
}
