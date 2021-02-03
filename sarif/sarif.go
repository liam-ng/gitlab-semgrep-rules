package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/ruleset"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/metadata"
)

type sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool struct {
		Driver struct {
			Name            string `json:"name"`
			SemanticVersion string `json:"semanticVersion"`
			Rules           []rule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []result `json:"results"`
}

type rule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties struct {
		Precision string   `json:"precision"`
		Tags      []string `json:"tags"`
	} `json:"properties"`
}

type result struct {
	RuleID  string `json:"ruleId"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI       string `json:"uri"`
				URIBaseID string `json:"uriBaseId"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
				EndLine     int `json:"endLine"`
				EndColumn   int `json:"endColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

var tagIDRegex = regexp.MustCompile(`(CWE)-([^:]+): (.+)`)

// TransformToGLSASTReport will take in a sarif file and output a GitLab SAST Report
// TODO https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317855 document level
// property (write tests for this)
// TODO no level prop is equal to level warning
// TODO all returns
func TransformToGLSASTReport(reader io.Reader, prependPath string) (*issue.Report, error) {
	s := sarif{}
	err := json.Unmarshal(readerToBytes(reader), &s)
	if err != nil {
		return nil, err
	}

	if s.Version != "2.1.0" {
		return nil, fmt.Errorf("version for SARIF is %s, but we only support 2.1.0", s.Version)
	}

	// TODO support multiple runs
	issues, err := transformRun(s.Runs[0], prependPath)
	if err != nil {
		return nil, err
	}

	report := issue.NewReport()
	report.Analyzer = metadata.AnalyzerID
	report.Config.Path = ruleset.PathSAST
	report.Vulnerabilities = issues
	return &report, nil
}

func readerToBytes(reader io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(reader)
	return buf.Bytes()
}

func countResults(runs []run) int {
	issuesLength := 0
	for _, r := range runs {
		issuesLength += len(r.Results)
	}
	return issuesLength
}

// TODO support multiple locations
func transformRun(r run, prependPath string) ([]issue.Issue, error) {
	if r.Tool.Driver.Name != "semgrep" {
		return nil, fmt.Errorf("Driver is %s, but we only support semgrep", r.Tool.Driver.Name)
	}

	ruleMap := make(map[string]rule)
	for _, rule := range r.Tool.Driver.Rules {
		ruleMap[rule.ID] = rule
	}

	issues := make([]issue.Issue, len(r.Results))
	for i, result := range r.Results {
		rule := ruleMap[result.RuleID]
		issues[i] = issue.Issue{
			Category: issue.CategorySast,
			Message:  result.Message.Text,
			Severity: severity(rule),
			Scanner:  metadata.IssueScanner,
			Location: issue.Location{
				File:      strings.TrimPrefix(result.Locations[0].PhysicalLocation.ArtifactLocation.URI, prependPath),
				LineStart: result.Locations[0].PhysicalLocation.Region.StartLine,
				LineEnd:   result.Locations[0].PhysicalLocation.Region.EndLine,
			},
			Identifiers: identifiers(rule),
		}
	}
	return issues, nil
}

// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317855
func severity(r rule) issue.SeverityLevel {
	switch r.DefaultConfiguration.Level {
	case "error":
		return issue.SeverityLevelCritical
	case "warning":
		return issue.SeverityLevelMedium
	case "note":
		return issue.SeverityLevelInfo
	case "none":
		return issue.SeverityLevelUnknown
	default:
		return issue.SeverityLevelMedium
	}
}

func identifiers(r rule) []issue.Identifier {
	ids := []issue.Identifier{
		{
			Type:  "semgrep_id",
			Name:  r.ID,
			Value: r.ID,
		},
	}

	for _, tag := range r.Properties.Tags {
		matches := tagIDRegex.FindStringSubmatch(tag)

		if matches != nil {
			switch matches[1] {
			case "CWE":
				ids = append(ids, issue.Identifier{
					Type:  issue.IdentifierTypeCWE,
					Name:  matches[2],
					Value: matches[3],
				})
			}
		}
	}

	return ids
}
