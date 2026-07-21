package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultEcosystem       = "auto"
	DefaultMinimumSeverity = "high"
	DefaultStrategy        = "minimum-safe"
	DefaultMaximumUpdates  = 5
)

type Job struct {
	Directory         string `json:"directory"`
	Ecosystem         string `json:"ecosystem"`
	MinimumSeverity   string `json:"minimum_severity"`
	Strategy          string `json:"strategy"`
	AllowMajor        bool   `json:"allow_major"`
	MaximumUpdates    int    `json:"maximum_updates"`
	Output            string `json:"output,omitempty"`
	ArtifactDirectory string `json:"artifact_directory,omitempty"`
}

func DefaultJob() Job {
	return Job{
		Directory:       ".",
		Ecosystem:       DefaultEcosystem,
		MinimumSeverity: DefaultMinimumSeverity,
		Strategy:        DefaultStrategy,
		AllowMajor:      false,
		MaximumUpdates:  DefaultMaximumUpdates,
		Output:          "result.json",
	}
}

func LoadJob(path string) (Job, error) {
	job := DefaultJob()
	if path == "" {
		return job, nil
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return job, err
	}
	if err := json.Unmarshal(raw, &job); err != nil {
		return job, err
	}
	return job.WithDefaults(), nil
}

func (j Job) WithDefaults() Job {
	if strings.TrimSpace(j.Directory) == "" {
		j.Directory = "."
	}
	if strings.TrimSpace(j.Ecosystem) == "" {
		j.Ecosystem = DefaultEcosystem
	}
	if strings.TrimSpace(j.MinimumSeverity) == "" {
		j.MinimumSeverity = DefaultMinimumSeverity
	}
	if strings.TrimSpace(j.Strategy) == "" {
		j.Strategy = DefaultStrategy
	}
	if j.MaximumUpdates == 0 {
		j.MaximumUpdates = DefaultMaximumUpdates
	}
	if strings.TrimSpace(j.Output) == "" {
		j.Output = "result.json"
	}
	return j
}

func (j Job) Validate() error {
	if j.Strategy != DefaultStrategy {
		return fmt.Errorf("unsupported strategy %q", j.Strategy)
	}
	if j.MaximumUpdates < 1 {
		return fmt.Errorf("maximum_updates must be greater than zero")
	}
	clean := filepath.Clean(j.Directory)
	if filepath.IsAbs(clean) {
		return fmt.Errorf("directory must be relative to the workspace")
	}
	if strings.HasPrefix(clean, "..") {
		return fmt.Errorf("directory must not escape the workspace")
	}
	if strings.TrimSpace(j.ArtifactDirectory) != "" {
		artifacts := filepath.Clean(j.ArtifactDirectory)
		if !filepath.IsAbs(artifacts) && strings.HasPrefix(artifacts, "..") {
			return fmt.Errorf("artifact_directory must not escape the workspace")
		}
	}
	return nil
}
