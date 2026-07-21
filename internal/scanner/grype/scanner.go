package grype

import (
	"context"
	"os"
	"os/exec"
)

type Runner struct{}

func (Runner) Scan(ctx context.Context, sbomPath, output string) error {
	out, err := os.Create(output)
	if err != nil {
		return err
	}
	defer out.Close()

	cmd := exec.CommandContext(ctx, "grype", "sbom:"+sbomPath, "-o", "json")
	cmd.Stdout = out
	return cmd.Run()
}
