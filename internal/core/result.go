package core

type Status string

const (
	StatusNoFinding      Status = "NO_FINDING"
	StatusVerifiedUpdate Status = "VERIFIED_UPDATE"
	StatusSkipped        Status = "SKIPPED"
	StatusFailed         Status = "FAILED"
	StatusUnsupported    Status = "UNSUPPORTED"
	StatusNeedsManual    Status = "NEEDS_MANUAL_REVIEW"
)

type Dependency struct {
	Name         string `json:"name"`
	From         string `json:"from"`
	To           string `json:"to"`
	Relationship string `json:"relationship"`
}

type Vulnerability struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
}

type Verification struct {
	TargetFindingsRemoved      bool `json:"target_findings_removed"`
	RemainingThresholdFindings int  `json:"remaining_threshold_findings"`
	NewCriticalFindings        int  `json:"new_critical_findings"`
	NewThresholdFindings       int  `json:"new_threshold_findings"`
	DependencyFilesValid       bool `json:"dependency_files_valid"`
}

type Result struct {
	Status          Status          `json:"status"`
	Ecosystem       string          `json:"ecosystem"`
	Directory       string          `json:"directory"`
	Dependency      *Dependency     `json:"dependency,omitempty"`
	Dependencies    []Dependency    `json:"dependencies,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	ChangedFiles    []string        `json:"changed_files,omitempty"`
	Verification    *Verification   `json:"verification,omitempty"`
	Message         string          `json:"message,omitempty"`
}
