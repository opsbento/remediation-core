package syft

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
)

type Runner struct{}

func (Runner) Generate(ctx context.Context, workdir, output string) error {
	cmd := exec.CommandContext(ctx, "syft", "dir:"+workdir, "--source-name", sourceName(workdir), "--source-version", "workspace", "-o", "syft-json="+filepath.Clean(output))
	return cmd.Run()
}

func (Runner) Evidence(ctx context.Context, workdir, output string) error {
	cmd := exec.CommandContext(ctx, "syft", "dir:"+workdir, "--source-name", sourceName(workdir), "--source-version", "workspace", "-o", "cyclonedx-json="+filepath.Clean(output))
	return cmd.Run()
}

func sourceName(workdir string) string {
	name := filepath.Base(filepath.Clean(workdir))
	if name == "." || name == string(filepath.Separator) || strings.TrimSpace(name) == "" {
		return "workspace"
	}
	return name
}
