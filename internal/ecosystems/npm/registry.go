package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

type Registry struct{}

func (Registry) Versions(packageName string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "npm", "view", packageName, "versions", "--json")
	cmd.Env = append(cmd.Environ(), "npm_config_fetch_timeout=120000", "npm_config_audit=false", "npm_config_fund=false")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("npm view versions: %w: %s", err, strings.TrimSpace(string(raw)))
	}
	var versions []string
	if err := json.Unmarshal(raw, &versions); err != nil {
		var single string
		if err := json.Unmarshal(raw, &single); err != nil {
			return nil, err
		}
		versions = []string{single}
	}
	return versions, nil
}
