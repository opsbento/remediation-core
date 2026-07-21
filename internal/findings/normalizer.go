package findings

import (
	"encoding/json"
	"strings"
)

type Finding struct {
	PackageName      string
	InstalledVersion string
	Ecosystem        string
	VulnerabilityID  string
	Severity         string
	FixState         string
	FixedVersions    []string
	PackageType      string
}

func NormalizeGrype(raw []byte, minimumSeverity string) ([]Finding, error) {
	var report struct {
		Matches []struct {
			Vulnerability struct {
				ID       string `json:"id"`
				Severity string `json:"severity"`
				Fix      struct {
					State    string   `json:"state"`
					Versions []string `json:"versions"`
				} `json:"fix"`
			} `json:"vulnerability"`
			Artifact struct {
				Name     string `json:"name"`
				Version  string `json:"version"`
				Type     string `json:"type"`
				Language string `json:"language"`
			} `json:"artifact"`
		} `json:"matches"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, err
	}

	var out []Finding
	for _, match := range report.Matches {
		if !SeverityAtLeast(match.Vulnerability.Severity, minimumSeverity) {
			continue
		}
		ecosystem := strings.ToLower(match.Artifact.Type)
		if ecosystem == "" {
			ecosystem = strings.ToLower(match.Artifact.Language)
		}
		if strings.EqualFold(match.Artifact.Type, "npm") {
			ecosystem = "npm"
		}
		out = append(out, Finding{
			PackageName:      match.Artifact.Name,
			InstalledVersion: match.Artifact.Version,
			Ecosystem:        ecosystem,
			VulnerabilityID:  match.Vulnerability.ID,
			Severity:         match.Vulnerability.Severity,
			FixState:         match.Vulnerability.Fix.State,
			FixedVersions:    match.Vulnerability.Fix.Versions,
			PackageType:      match.Artifact.Type,
		})
	}
	return out, nil
}

func SeverityAtLeast(got, minimum string) bool {
	rank := map[string]int{
		"negligible": 0,
		"low":        1,
		"medium":     2,
		"moderate":   2,
		"high":       3,
		"critical":   4,
	}
	return rank[strings.ToLower(got)] >= rank[strings.ToLower(minimum)]
}
