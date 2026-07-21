package npm

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func (Adapter) Validate(ctx context.Context, workdir string) error {
	cmd := exec.CommandContext(ctx, "npm", "install", "--package-lock-only", "--ignore-scripts")
	cmd.Dir = workdir
	cmd.Env = append(cmd.Environ(), "npm_config_fund=false", "npm_config_audit=false")
	if raw, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("npm validate lockfile: %w: %s", err, strings.TrimSpace(string(raw)))
	}
	return nil
}

func (Adapter) AllowedChangedFiles() []string {
	return []string{"package.json", "package-lock.json"}
}
