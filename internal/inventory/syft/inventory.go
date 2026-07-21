package syft

import (
	"context"
	"os/exec"
	"path/filepath"
)

type Runner struct{}

func (Runner) Generate(ctx context.Context, workdir, output string) error {
	cmd := exec.CommandContext(ctx, "syft", "dir:"+workdir, "-o", "syft-json="+filepath.Clean(output))
	return cmd.Run()
}

func (Runner) Evidence(ctx context.Context, workdir, output string) error {
	cmd := exec.CommandContext(ctx, "syft", "dir:"+workdir, "-o", "cyclonedx-json="+filepath.Clean(output))
	return cmd.Run()
}
