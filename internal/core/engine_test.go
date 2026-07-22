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
	if len(result.Dependencies) != 1 || result.Dependencies[0].Name != "pkg" {
		t.Fatalf("unexpected dependencies result: %#v", result.Dependencies)
	}
	if result.Verification == nil || !result.Verification.TargetFindingsRemoved || !result.Verification.DependencyFilesValid {
		t.Fatalf("unexpected verification: %#v", result.Verification)
	}
	if result.Verification.RemainingThresholdFindings != 0 {
		t.Fatalf("unexpected remaining findings: %#v", result.Verification)
	}
}

func TestEngineUpdatesMultipleDependenciesBySeverityPriority(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	engine := testEngine([]scanReport{
		{findings: `{
		  "matches": [
		    {
		      "vulnerability": {"id":"CVE-MEDIUM","severity":"Medium","fix":{"state":"fixed","versions":["1.0.1"]}},
		      "artifact": {"name":"alpha","version":"1.0.0","type":"npm","language":"npm"}
		    },
		    {
		      "vulnerability": {"id":"CVE-CRITICAL","severity":"Critical","fix":{"state":"fixed","versions":["1.0.1"]}},
		      "artifact": {"name":"beta","version":"1.0.0","type":"npm","language":"npm"}
		    },
		    {
		      "vulnerability": {"id":"CVE-HIGH","severity":"High","fix":{"state":"fixed","versions":["1.0.1"]}},
		      "artifact": {"name":"gamma","version":"1.0.0","type":"npm","language":"npm"}
		    }
		  ]
		}`},
		{findings: `{"matches":[]}`},
	})
	engine.Adapters = []ecosystems.Adapter{
		&fakeAdapter{
			deps: []ecosystems.Dependency{
				{Name: "alpha", Version: "1.0.0", Relationship: "direct", Section: "dependencies"},
				{Name: "beta", Version: "1.0.0", Relationship: "direct", Section: "dependencies"},
				{Name: "gamma", Version: "1.0.0", Relationship: "direct", Section: "dependencies"},
			},
			valid: true,
		},
	}

	result, err := engine.Run(context.Background(), Job{
		Directory:       ".",
		Ecosystem:       "npm",
		MinimumSeverity: "medium",
		Strategy:        "minimum-safe",
		MaximumUpdates:  2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusVerifiedUpdate {
		t.Fatalf("got status %q, want %q: %s", result.Status, StatusVerifiedUpdate, result.Message)
	}
	if len(result.Dependencies) != 2 {
		t.Fatalf("got %d dependencies, want 2: %#v", len(result.Dependencies), result.Dependencies)
	}
	if result.Dependencies[0].Name != "beta" || result.Dependencies[1].Name != "gamma" {
		t.Fatalf("unexpected priority order: %#v", result.Dependencies)
	}
	if result.Dependency == nil || result.Dependency.Name != "beta" {
		t.Fatalf("unexpected backward-compatible dependency: %#v", result.Dependency)
	}
}

func TestEngineRejectsCandidateWithNewThresholdFinding(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	engine := testEngine([]scanReport{
		{findings: grypeReport("pkg", "1.0.0", "CVE-OLD", "High", "1.0.1")},
		{findings: grypeReport("pkg", "1.0.1", "CVE-NEW", "High", "1.0.2")},
		{findings: `{"matches":[]}`},
		{findings: `{"matches":[]}`},
	})
	engine.Registry = fakeRegistry{"1.0.1", "1.0.2", "2.0.0"}

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
	if result.Dependency == nil || result.Dependency.To != "1.0.2" {
		t.Fatalf("got dependency %#v, want target 1.0.2", result.Dependency)
	}
	if result.Verification == nil || result.Verification.NewThresholdFindings != 0 {
		t.Fatalf("unexpected verification: %#v", result.Verification)
	}
}

func TestEngineFailsWhenThresholdFindingsRemain(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	engine := testEngine([]scanReport{
		{findings: `{
		  "matches": [
		    {
		      "vulnerability": {"id":"CVE-PKG","severity":"High","fix":{"state":"fixed","versions":["1.0.1"]}},
		      "artifact": {"name":"pkg","version":"1.0.0","type":"npm","language":"npm"}
		    },
		    {
		      "vulnerability": {"id":"CVE-OTHER","severity":"High","fix":{"state":"fixed","versions":["1.0.1"]}},
		      "artifact": {"name":"other","version":"1.0.0","type":"npm","language":"npm"}
		    }
		  ]
		}`},
		{findings: grypeReport("other", "1.0.0", "CVE-OTHER", "High", "1.0.1")},
		{findings: grypeReport("other", "1.0.0", "CVE-OTHER", "High", "1.0.1")},
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
	if result.Status != StatusFailed {
		t.Fatalf("got status %q, want %q", result.Status, StatusFailed)
	}
	if result.Verification == nil || result.Verification.RemainingThresholdFindings != 1 {
		t.Fatalf("unexpected verification: %#v", result.Verification)
	}
}

func TestEngineUpdatesDirectParentForTransitiveFinding(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	engine := testEngine([]scanReport{
		{findings: grypeReport("qs", "6.7.0", "CVE-QS", "High", "6.7.3")},
		{findings: `{"matches":[]}`},
		{findings: `{"matches":[]}`},
	})
	engine.Registry = fakeRegistry{"4.17.1", "4.18.0", "4.19.2", "5.0.0"}
	engine.Adapters = []ecosystems.Adapter{
		&fakeAdapter{
			deps: []ecosystems.Dependency{
				{Name: "express", Version: "4.17.1", Relationship: "direct", Section: "dependencies"},
			},
			parents: map[string][]ecosystems.Dependency{
				"qs": {
					{Name: "express", Version: "4.17.1", Relationship: "direct-parent", Section: "dependencies"},
				},
			},
			valid: true,
		},
	}

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
	if result.Dependency == nil || result.Dependency.Name != "express" || result.Dependency.To != "4.18.0" || result.Dependency.Relationship != "direct-parent" {
		t.Fatalf("unexpected dependency result: %#v", result.Dependency)
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
	if len(result.ManualReviews) != 1 || result.ManualReviews[0].Dependency != "pkg" {
		t.Fatalf("unexpected manual review diagnostics: %#v", result.ManualReviews)
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
	deps    []ecosystems.Dependency
	parents map[string][]ecosystems.Dependency
	valid   bool
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

func (a *fakeAdapter) DirectParents(workdir, packageName string) ([]ecosystems.Dependency, error) {
	return a.parents[packageName], nil
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
