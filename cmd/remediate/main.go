package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/opsbento/remediation-core/internal/core"
)

func main() {
	var jobFile string
	job := core.DefaultJob()
	flag.StringVar(&jobFile, "job", "", "Path to JSON job file")
	flag.StringVar(&job.Directory, "directory", job.Directory, "Workspace directory to remediate")
	flag.StringVar(&job.Ecosystem, "ecosystem", job.Ecosystem, "Ecosystem to remediate: auto or npm")
	flag.StringVar(&job.MinimumSeverity, "minimum-severity", job.MinimumSeverity, "Minimum vulnerability severity")
	flag.StringVar(&job.Strategy, "strategy", job.Strategy, "Update strategy")
	flag.BoolVar(&job.AllowMajor, "allow-major", job.AllowMajor, "Allow major version updates")
	flag.IntVar(&job.MaximumUpdates, "maximum-updates", job.MaximumUpdates, "Maximum dependencies to update")
	flag.StringVar(&job.Output, "output", job.Output, "Result JSON path")
	flag.StringVar(&job.ArtifactDirectory, "artifact-directory", job.ArtifactDirectory, "Directory for SBOM and scan artifacts")
	flag.Parse()

	if jobFile != "" {
		loaded, err := core.LoadJob(jobFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load job: %v\n", err)
			os.Exit(2)
		}
		job = loaded
	}

	engine := core.NewEngine()
	result, err := engine.Run(context.Background(), job)
	if writeErr := core.WriteResult(job.Output, result); writeErr != nil {
		fmt.Fprintf(os.Stderr, "write result: %v\n", writeErr)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "remediation failed: %v\n", err)
		os.Exit(1)
	}
	if result.Status != core.StatusVerifiedUpdate && result.Status != core.StatusNoFinding && result.Status != core.StatusSkipped {
		os.Exit(1)
	}
}
