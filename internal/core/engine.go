package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/opsbento/remediation-core/internal/ecosystems"
	"github.com/opsbento/remediation-core/internal/ecosystems/npm"
	"github.com/opsbento/remediation-core/internal/findings"
	"github.com/opsbento/remediation-core/internal/inventory/syft"
	"github.com/opsbento/remediation-core/internal/resolver"
	"github.com/opsbento/remediation-core/internal/scanner/grype"
	"github.com/opsbento/remediation-core/internal/verifier"
)

type Engine struct {
	Inventory     Inventory
	Scanner       Scanner
	Registry      resolver.Registry
	ChangeTracker ChangeTracker
	Adapters      []ecosystems.Adapter
}

type Inventory interface {
	Generate(ctx context.Context, workdir, output string) error
	Evidence(ctx context.Context, workdir, output string) error
}

type Scanner interface {
	Scan(ctx context.Context, sbomPath, output string) error
}

type ChangeTracker interface {
	GitAvailable(ctx context.Context, workdir string) bool
	ChangedFiles(ctx context.Context, workdir string) ([]string, error)
}

func NewEngine() Engine {
	return Engine{
		Inventory:     syft.Runner{},
		Scanner:       grype.Runner{},
		Registry:      npm.Registry{},
		ChangeTracker: gitChangeTracker{},
		Adapters:      []ecosystems.Adapter{npm.NewAdapter()},
	}
}

func (e Engine) Run(ctx context.Context, job Job) (Result, error) {
	job = job.WithDefaults()
	if err := job.Validate(); err != nil {
		return failed(job, err), err
	}

	workdir := filepath.Clean(job.Directory)
	adapter, err := e.detectAdapter(workdir, job.Ecosystem)
	if err != nil {
		return Result{Status: StatusUnsupported, Directory: job.Directory, Message: err.Error()}, err
	}

	artifactDir, cleanup, err := artifactDirectory(job)
	if err != nil {
		return failed(job, err), err
	}
	if cleanup {
		defer os.RemoveAll(artifactDir)
	}

	beforeSBOM := filepath.Join(artifactDir, "sbom.before.json")
	beforeEvidence := filepath.Join(artifactDir, "sbom.before.cdx.json")
	beforeFindings := filepath.Join(artifactDir, "findings.before.json")
	if err := e.Inventory.Generate(ctx, workdir, beforeSBOM); err != nil {
		return failed(job, fmt.Errorf("generate SBOM: %w", err)), err
	}
	if err := e.Inventory.Evidence(ctx, workdir, beforeEvidence); err != nil {
		return failed(job, fmt.Errorf("generate evidence SBOM: %w", err)), err
	}
	if err := e.Scanner.Scan(ctx, beforeSBOM, beforeFindings); err != nil {
		return failed(job, fmt.Errorf("scan SBOM: %w", err)), err
	}
	beforeRaw, err := os.ReadFile(beforeFindings)
	if err != nil {
		return failed(job, err), err
	}
	before, err := findings.NormalizeGrype(beforeRaw, job.MinimumSeverity)
	if err != nil {
		return failed(job, err), err
	}
	groups := findings.GroupByDependency(filterEcosystem(before, adapter.Name()))
	if len(groups) == 0 {
		return Result{Status: StatusNoFinding, Ecosystem: adapter.Name(), Directory: job.Directory}, nil
	}
	if len(groups) > job.MaximumUpdates {
		groups = groups[:job.MaximumUpdates]
	}

	deps, err := adapter.Parse(workdir)
	if err != nil {
		return failed(job, err), err
	}
	group := groups[0]
	current, ok := verifier.HasDirectDependency(deps, group.PackageName)
	if !ok {
		return Result{Status: StatusSkipped, Ecosystem: adapter.Name(), Directory: job.Directory, Message: "only direct dependencies are supported"}, nil
	}

	target, err := resolver.ResolveMinimumSafe(group, e.Registry, resolver.Policy{AllowMajor: job.AllowMajor})
	if err != nil {
		return Result{Status: StatusNeedsManual, Ecosystem: adapter.Name(), Directory: job.Directory, Message: err.Error()}, nil
	}

	updateCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := adapter.Update(updateCtx, workdir, group.PackageName, target); err != nil {
		return failed(job, fmt.Errorf("update dependency: %w", err)), err
	}
	valid := adapter.Validate(updateCtx, workdir) == nil

	afterSBOM := filepath.Join(artifactDir, "sbom.after.json")
	afterEvidence := filepath.Join(artifactDir, "sbom.after.cdx.json")
	afterFindings := filepath.Join(artifactDir, "findings.after.json")
	if err := e.Inventory.Generate(ctx, workdir, afterSBOM); err != nil {
		return failed(job, fmt.Errorf("generate after SBOM: %w", err)), err
	}
	if err := e.Inventory.Evidence(ctx, workdir, afterEvidence); err != nil {
		return failed(job, fmt.Errorf("generate after evidence SBOM: %w", err)), err
	}
	if err := e.Scanner.Scan(ctx, afterSBOM, afterFindings); err != nil {
		return failed(job, fmt.Errorf("scan after SBOM: %w", err)), err
	}
	afterRaw, err := os.ReadFile(afterFindings)
	if err != nil {
		return failed(job, err), err
	}
	after, err := findings.NormalizeGrype(afterRaw, "low")
	if err != nil {
		return failed(job, err), err
	}

	changed := []string{}
	if e.ChangeTracker.GitAvailable(ctx, workdir) {
		changed, err = e.ChangeTracker.ChangedFiles(ctx, workdir)
		if err != nil {
			return failed(job, err), err
		}
		if err := verifier.GuardAllowed(changed, adapter.AllowedChangedFiles()); err != nil {
			return failed(job, err), err
		}
	}

	vulns := vulnerabilities(group.Findings)
	vulnIDs := make([]string, 0, len(vulns))
	for _, vuln := range vulns {
		vulnIDs = append(vulnIDs, vuln.ID)
	}
	verification := Verification{
		TargetFindingsRemoved: verifier.TargetFindingsRemoved(after, group.PackageName, vulnIDs),
		NewCriticalFindings:   verifier.NewCriticalFindings(before, after),
		DependencyFilesValid:  valid,
	}
	status := StatusVerifiedUpdate
	if !verification.TargetFindingsRemoved || verification.NewCriticalFindings > 0 || !verification.DependencyFilesValid {
		status = StatusFailed
	}

	return Result{
		Status:    status,
		Ecosystem: adapter.Name(),
		Directory: job.Directory,
		Dependency: &Dependency{
			Name:         group.PackageName,
			From:         current.Version,
			To:           target,
			Relationship: current.Relationship,
		},
		Vulnerabilities: vulns,
		ChangedFiles:    changed,
		Verification:    &verification,
	}, nil
}

func artifactDirectory(job Job) (string, bool, error) {
	if job.ArtifactDirectory == "" {
		dir, err := os.MkdirTemp("", "remediation-core-*")
		return dir, true, err
	}
	dir := filepath.Clean(job.ArtifactDirectory)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", false, err
	}
	return dir, false, nil
}

type gitChangeTracker struct{}

func (gitChangeTracker) GitAvailable(ctx context.Context, workdir string) bool {
	return verifier.GitAvailable(ctx, workdir)
}

func (gitChangeTracker) ChangedFiles(ctx context.Context, workdir string) ([]string, error) {
	return verifier.ChangedFiles(ctx, workdir)
}

func WriteResult(path string, result Result) error {
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0644)
}

func (e Engine) detectAdapter(workdir, requested string) (ecosystems.Adapter, error) {
	for _, adapter := range e.Adapters {
		if requested != "auto" && requested != adapter.Name() {
			continue
		}
		ok, err := adapter.Detect(workdir)
		if err != nil {
			return nil, err
		}
		if ok {
			return adapter, nil
		}
	}
	return nil, fmt.Errorf("no supported ecosystem detected")
}

func filterEcosystem(fs []findings.Finding, ecosystem string) []findings.Finding {
	var out []findings.Finding
	for _, finding := range fs {
		if finding.Ecosystem == "" || finding.Ecosystem == ecosystem {
			out = append(out, finding)
		}
	}
	return out
}

func vulnerabilities(fs []findings.Finding) []Vulnerability {
	seen := map[string]bool{}
	var out []Vulnerability
	for _, finding := range fs {
		if seen[finding.VulnerabilityID] {
			continue
		}
		seen[finding.VulnerabilityID] = true
		out = append(out, Vulnerability{ID: finding.VulnerabilityID, Severity: finding.Severity})
	}
	return out
}

func failed(job Job, err error) Result {
	return Result{Status: StatusFailed, Directory: job.Directory, Message: err.Error()}
}
