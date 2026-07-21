package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/opsbento/remediation-core/internal/ecosystems"
)

func TestEngineNoFindingPreservesBeforeArtifacts(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	artifacts := "reports"
	engine := testEngine([]scanReport{
		{findings: `{"matches":[]}`},
	})

	result, err := engine.Run(context.Background(), Job{
		Directory:         ".",
		Ecosystem:         "npm",
		MinimumSeverity:   "high",
		Strategy:          "minimum-safe",
		MaximumUpdates:    1,
		ArtifactDirectory: artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusNoFinding {
		t.Fatalf("got status %q, want %q", result.Status, StatusNoFinding)
	}
	for _, name := range []string{"sbom.before.json", "sbom.before.cdx.json", "findings.before.json"} {
		if _, err := os.Stat(filepath.Join(artifacts, name)); err != nil {
			t.Fatalf("expected artifact %s: %v", name, err)
		}
	}
}

func TestEngineVerifiedUpdate(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	engine := testEngine([]scanReport{
		{findings: grypeReport("pkg", "1.0.0", "CVE-1", "High", "1.0.1")},
		{findings: `{"matches":[]}`},
	})

	result, err := engine.Run(context.Background(), Job{
		Directory:       ".",
		Ecosystem:       "npm",
		MinimumSeverity: "high",
		Strategy:        "minimum-safe",
		MaximumUpdates:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusVerifiedUpdate {
		t.Fatalf("got status %q, want %q: %s", result.Status, StatusVerifiedUpdate, result.Message)
	}
	if result.Dependency == nil || result.Dependency.Name != "pkg" || result.Dependency.To != "1.0.1" {
		t.Fatalf("unexpected dependency result: %#v", result.Dependency)
	}
	if result.Verification == nil || !result.Verification.TargetFindingsRemoved || !result.Verification.DependencyFilesValid {
		t.Fatalf("unexpected verification: %#v", result.Verification)
	}
}

func TestEngineMajorOnlyFixNeedsManualReview(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	engine := testEngine([]scanReport{
		{findings: grypeReport("pkg", "1.0.0", "CVE-1", "High", "2.0.0")},
	})
	engine.Registry = fakeRegistry{"2.0.0"}

	result, err := engine.Run(context.Background(), Job{
		Directory:       ".",
		Ecosystem:       "npm",
		MinimumSeverity: "high",
		Strategy:        "minimum-safe",
		MaximumUpdates:  1,
		AllowMajor:      false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusNeedsManual {
		t.Fatalf("got status %q, want %q", result.Status, StatusNeedsManual)
	}
}

func TestEngineRejectsUnexpectedChangedFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	engine := testEngine([]scanReport{
		{findings: grypeReport("pkg", "1.0.0", "CVE-1", "High", "1.0.1")},
		{findings: `{"matches":[]}`},
	})
	engine.ChangeTracker = fakeChangeTracker{available: true, files: []string{"README.md"}}

	result, err := engine.Run(context.Background(), Job{
		Directory:       ".",
		Ecosystem:       "npm",
		MinimumSeverity: "high",
		Strategy:        "minimum-safe",
		MaximumUpdates:  1,
	})
	if err == nil {
		t.Fatal("expected unexpected changed file error")
	}
	if result.Status != StatusFailed {
		t.Fatalf("got status %q, want %q", result.Status, StatusFailed)
	}
}

func testEngine(reports []scanReport) Engine {
	return Engine{
		Inventory: fakeInventory{},
		Scanner:   &fakeScanner{reports: reports},
		Registry:  fakeRegistry{"1.0.1", "2.0.0"},
		Adapters: []ecosystems.Adapter{
			&fakeAdapter{
				deps: []ecosystems.Dependency{
					{Name: "pkg", Version: "1.0.0", Relationship: "direct", Section: "dependencies"},
				},
				valid: true,
			},
		},
		ChangeTracker: fakeChangeTracker{},
	}
}

type fakeInventory struct{}

func (fakeInventory) Generate(ctx context.Context, workdir, output string) error {
	return os.WriteFile(output, []byte(`{"artifacts":[]}`), 0644)
}

func (fakeInventory) Evidence(ctx context.Context, workdir, output string) error {
	return os.WriteFile(output, []byte(`{"components":[]}`), 0644)
}

type scanReport struct {
	findings string
}

type fakeScanner struct {
	reports []scanReport
	calls   int
}

func (s *fakeScanner) Scan(ctx context.Context, sbomPath, output string) error {
	report := scanReport{findings: `{"matches":[]}`}
	if s.calls < len(s.reports) {
		report = s.reports[s.calls]
	}
	s.calls++
	return os.WriteFile(output, []byte(report.findings), 0644)
}

type fakeRegistry []string

func (r fakeRegistry) Versions(packageName string) ([]string, error) {
	return []string(r), nil
}

type fakeAdapter struct {
	deps  []ecosystems.Dependency
	valid bool
}

func (a *fakeAdapter) Name() string {
	return "npm"
}

func (a *fakeAdapter) Detect(workdir string) (bool, error) {
	return true, nil
}

func (a *fakeAdapter) Parse(workdir string) ([]ecosystems.Dependency, error) {
	return a.deps, nil
}

func (a *fakeAdapter) Update(ctx context.Context, workdir, packageName, targetVersion string) error {
	for i := range a.deps {
		if a.deps[i].Name == packageName {
			a.deps[i].Version = targetVersion
		}
	}
	return nil
}

func (a *fakeAdapter) Validate(ctx context.Context, workdir string) error {
	if a.valid {
		return nil
	}
	return os.ErrInvalid
}

func (a *fakeAdapter) AllowedChangedFiles() []string {
	return []string{"package.json", "package-lock.json"}
}

type fakeChangeTracker struct {
	available bool
	files     []string
}

func (c fakeChangeTracker) GitAvailable(ctx context.Context, workdir string) bool {
	return c.available
}

func (c fakeChangeTracker) ChangedFiles(ctx context.Context, workdir string) ([]string, error) {
	return c.files, nil
}

func grypeReport(packageName, version, vulnID, severity, fixed string) string {
	return `{
	  "matches": [{
	    "vulnerability": {
	      "id": "` + vulnID + `",
	      "severity": "` + severity + `",
	      "fix": {"state": "fixed", "versions": ["` + fixed + `"]}
	    },
	    "artifact": {
	      "name": "` + packageName + `",
	      "version": "` + version + `",
	      "type": "npm",
	      "language": "npm"
	    }
	  }]
	}`
}
