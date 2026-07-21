package npm

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

func (Adapter) Update(ctx context.Context, workdir, packageName, targetVersion string) error {
	cmd := exec.CommandContext(ctx, "npm", "install", packageName+"@"+targetVersion, "--save-exact", "--ignore-scripts")
	cmd.Dir = workdir
	cmd.Env = append(cmd.Environ(), "npm_config_fund=false", "npm_config_audit=false")
	if raw, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("npm install %s@%s: %w: %s", packageName, targetVersion, err, strings.TrimSpace(string(raw)))
	}
	return nil
}
