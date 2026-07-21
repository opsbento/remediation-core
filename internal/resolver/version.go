package resolver

import (
	"fmt"
	"strconv"
	"strings"
)

type Version struct {
	Major int
	Minor int
	Patch int
	Raw   string
}

func ParseVersion(raw string) (Version, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if trimmed == "" || strings.Contains(trimmed, "-") {
		return Version{}, fmt.Errorf("unsupported version %q", raw)
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) < 1 || len(parts) > 3 {
		return Version{}, fmt.Errorf("unsupported version %q", raw)
	}
	nums := [3]int{}
	for i, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil {
			return Version{}, fmt.Errorf("unsupported version %q", raw)
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Raw: trimmed}, nil
}

func Compare(a, b string) int {
	av, aerr := ParseVersion(a)
	bv, berr := ParseVersion(b)
	if aerr != nil || berr != nil {
		return strings.Compare(a, b)
	}
	switch {
	case av.Major != bv.Major:
		return cmpInt(av.Major, bv.Major)
	case av.Minor != bv.Minor:
		return cmpInt(av.Minor, bv.Minor)
	case av.Patch != bv.Patch:
		return cmpInt(av.Patch, bv.Patch)
	default:
		return 0
	}
}

func IsPrerelease(raw string) bool {
	return strings.Contains(raw, "-")
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}
