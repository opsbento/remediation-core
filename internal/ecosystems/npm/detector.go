package npm

import (
	"os"
	"path/filepath"

	"github.com/opsbento/remediation-core/internal/ecosystems"
)

type Adapter struct{}

func NewAdapter() Adapter {
	return Adapter{}
}

func (Adapter) Name() string {
	return "npm"
}

func (Adapter) Detect(workdir string) (bool, error) {
	if _, err := os.Stat(filepath.Join(workdir, "package.json")); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if _, err := os.Stat(filepath.Join(workdir, "package-lock.json")); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	pkg, err := ParsePackageJSON(workdir)
	if err != nil {
		return false, err
	}
	return pkg.Workspaces == nil, nil
}

func (Adapter) Parse(workdir string) ([]ecosystems.Dependency, error) {
	return DirectDependencies(workdir)
}
