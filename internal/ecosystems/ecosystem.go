package ecosystems

import "context"

type Dependency struct {
	Name         string
	Version      string
	Relationship string
	Section      string
}

type Adapter interface {
	Name() string
	Detect(workdir string) (bool, error)
	Parse(workdir string) ([]Dependency, error)
	Update(ctx context.Context, workdir, packageName, targetVersion string) error
	Validate(ctx context.Context, workdir string) error
	AllowedChangedFiles() []string
}

type ParentResolver interface {
	DirectParents(workdir, packageName string) ([]Dependency, error)
}
