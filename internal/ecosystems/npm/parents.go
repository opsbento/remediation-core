package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/opsbento/remediation-core/internal/ecosystems"
)

type lockfile struct {
	Packages map[string]lockPackage `json:"packages"`
}

type lockPackage struct {
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func (Adapter) DirectParents(workdir, packageName string) ([]ecosystems.Dependency, error) {
	raw, err := os.ReadFile(filepath.Join(workdir, "package-lock.json"))
	if err != nil {
		return nil, err
	}
	var lock lockfile
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	root := lock.Packages[""]
	var directNames []string
	seenDirect := map[string]bool{}
	addNames := func(deps map[string]string) {
		for name := range deps {
			if seenDirect[name] {
				continue
			}
			seenDirect[name] = true
			directNames = append(directNames, name)
		}
	}
	addNames(root.Dependencies)
	addNames(root.DevDependencies)
	addNames(root.OptionalDependencies)
	sort.Strings(directNames)

	var parents []ecosystems.Dependency
	for _, directName := range directNames {
		directPath := lockPath(directName)
		directPkg, ok := lock.Packages[directPath]
		if !ok {
			continue
		}
		if directName == packageName || dependencyClosureContains(lock.Packages, directPath, packageName, map[string]bool{}) {
			parents = append(parents, ecosystems.Dependency{
				Name:         directName,
				Version:      directPkg.Version,
				Relationship: "direct-parent",
				Section:      "dependencies",
			})
		}
	}
	return parents, nil
}

func dependencyClosureContains(packages map[string]lockPackage, path, packageName string, seen map[string]bool) bool {
	if seen[path] {
		return false
	}
	seen[path] = true
	pkg := packages[path]
	for child := range pkg.Dependencies {
		if child == packageName {
			return true
		}
		childPath := nestedLockPath(path, child)
		if _, ok := packages[childPath]; !ok {
			childPath = lockPath(child)
		}
		if dependencyClosureContains(packages, childPath, packageName, seen) {
			return true
		}
	}
	return false
}

func lockPath(packageName string) string {
	return filepath.ToSlash(filepath.Join("node_modules", packageName))
}

func nestedLockPath(parentPath, packageName string) string {
	return filepath.ToSlash(filepath.Join(parentPath, "node_modules", packageName))
}
