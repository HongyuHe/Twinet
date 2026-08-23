package harness

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const MutationSuiteAPIVersion = "twinet.dev/v1"
const MutationSuiteKind = "CompactMutationSuite"

// MutationSuite is a versioned release-gate input. Every case must map to one
// exact rubric check occurrence and contain deterministic file transformations.
type MutationSuite struct {
	APIVersion string         `yaml:"apiVersion" json:"apiVersion"`
	Kind       string         `yaml:"kind" json:"kind"`
	Cases      []MutationCase `yaml:"cases" json:"cases"`
}

type MutationCase struct {
	Name                string              `yaml:"name" json:"name"`
	Required            CoverageRequirement `yaml:"required" json:"required"`
	ExpectedCheckStatus string              `yaml:"expected_check_status" json:"expected_check_status"`
	Transforms          []MutationTransform `yaml:"transforms" json:"transforms"`
}

type MutationTransform struct {
	File    string `yaml:"file" json:"file"`
	Find    string `yaml:"find,omitempty" json:"find,omitempty"`
	Replace string `yaml:"replace,omitempty" json:"replace,omitempty"`
	Append  string `yaml:"append,omitempty" json:"append,omitempty"`
}

func LoadMutationSuite(path string) (*MutationSuite, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseMutationSuite(raw)
}

// ParseMutationSuite validates exactly the bytes that will be sealed into an
// attestation. Callers that already hold a digestable release artifact must not
// parse one filesystem revision and sign a later one.
func ParseMutationSuite(raw []byte) (*MutationSuite, error) {
	var suite MutationSuite
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&suite); err != nil {
		return nil, err
	}
	if err := suite.Validate(nil); err != nil {
		return nil, err
	}
	return &suite, nil
}

func (s MutationSuite) Validate(required []CoverageRequirement) error {
	if s.APIVersion != MutationSuiteAPIVersion {
		return fmt.Errorf("mutation suite apiVersion %q, want %q", s.APIVersion, MutationSuiteAPIVersion)
	}
	if s.Kind != MutationSuiteKind {
		return fmt.Errorf("mutation suite kind %q, want %q", s.Kind, MutationSuiteKind)
	}
	if len(s.Cases) == 0 {
		return fmt.Errorf("mutation suite has no cases")
	}
	seenNames := map[string]bool{}
	seenCoverage := map[string]bool{}
	for _, mutation := range s.Cases {
		if !safeMutationName(mutation.Name) || seenNames[mutation.Name] {
			return fmt.Errorf("mutation suite has missing or duplicate case name %q", mutation.Name)
		}
		seenNames[mutation.Name] = true
		if !mutation.Required.Valid() || seenCoverage[mutation.Required.Key()] {
			return fmt.Errorf("mutation %q has missing or duplicate rubric coverage", mutation.Name)
		}
		seenCoverage[mutation.Required.Key()] = true
		if mutation.ExpectedCheckStatus == "" || mutation.ExpectedCheckStatus == "pass" {
			return fmt.Errorf("mutation %q must require a non-pass check status", mutation.Name)
		}
		if len(mutation.Transforms) == 0 {
			return fmt.Errorf("mutation %q has no transformations", mutation.Name)
		}
		for _, transform := range mutation.Transforms {
			if transform.File == "" || (transform.Append == "" && transform.Find == "") {
				return fmt.Errorf("mutation %q has an empty transformation", mutation.Name)
			}
			if transform.Find != "" && transform.Replace == "" {
				return fmt.Errorf("mutation %q has find without replace", mutation.Name)
			}
		}
	}
	if required != nil {
		want := map[string]bool{}
		for _, coverage := range required {
			if !coverage.Valid() || want[coverage.Key()] {
				return fmt.Errorf("required coverage is invalid or duplicated: %s", coverage.Key())
			}
			want[coverage.Key()] = true
		}
		if len(want) != len(seenCoverage) {
			return fmt.Errorf("mutation coverage count %d does not match required %d", len(seenCoverage), len(want))
		}
		var missing []string
		for key := range want {
			if !seenCoverage[key] {
				missing = append(missing, key)
			}
		}
		sort.Strings(missing)
		if len(missing) > 0 {
			return fmt.Errorf("mutation suite is missing rubric coverage: %v", missing)
		}
	}
	return nil
}

func safeMutationName(name string) bool {
	return name != "" && name != "." && name != ".." &&
		!strings.ContainsAny(name, `/\`) && !strings.Contains(name, "..")
}
