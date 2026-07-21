package findings

import "sort"

type Group struct {
	PackageName      string
	InstalledVersion string
	Ecosystem        string
	Findings         []Finding
}

func GroupByDependency(in []Finding) []Group {
	groups := map[string]*Group{}
	for _, finding := range in {
		key := finding.Ecosystem + "/" + finding.PackageName + "@" + finding.InstalledVersion
		group := groups[key]
		if group == nil {
			group = &Group{
				PackageName:      finding.PackageName,
				InstalledVersion: finding.InstalledVersion,
				Ecosystem:        finding.Ecosystem,
			}
			groups[key] = group
		}
		group.Findings = append(group.Findings, finding)
	}

	out := make([]Group, 0, len(groups))
	for _, group := range groups {
		out = append(out, *group)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem == out[j].Ecosystem {
			return out[i].PackageName < out[j].PackageName
		}
		return out[i].Ecosystem < out[j].Ecosystem
	})
	return out
}
