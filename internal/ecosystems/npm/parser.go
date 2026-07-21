package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/opsbento/remediation-core/internal/ecosystems"
)

type PackageJSON struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	Workspaces           any               `json:"workspaces,omitempty"`
}

func ParsePackageJSON(workdir string) (PackageJSON, error) {
	raw, err := os.ReadFile(filepath.Join(workdir, "package.json"))
	if err != nil {
		return PackageJSON{}, err
	}
	var pkg PackageJSON
	if err := json.Unmarshal(raw, &pkg); err != nil {
		return PackageJSON{}, err
	}
	return pkg, nil
}

func DirectDependencies(workdir string) ([]ecosystems.Dependency, error) {
	pkg, err := ParsePackageJSON(workdir)
	if err != nil {
		return nil, err
	}
	var out []ecosystems.Dependency
	add := func(section string, deps map[string]string) {
		for name, version := range deps {
			out = append(out, ecosystems.Dependency{
				Name:         name,
				Version:      strings.TrimLeft(version, "^~>=< "),
				Relationship: "direct",
				Section:      section,
			})
		}
	}
	add("dependencies", pkg.Dependencies)
	add("devDependencies", pkg.DevDependencies)
	add("optionalDependencies", pkg.OptionalDependencies)
	return out, nil
}
