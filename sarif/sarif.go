package sarif

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v2"
	"gitlab.com/gitlab-org/security-products/analyzers/ruleset"
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
	HelpURI			 string `json:"helpUri"`
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

const vulnerabilityMessageMaxLength = 400

var tagIDRegex = regexp.MustCompile(`([^-]+)-([^:]+): (.+)`)

// TransformToGLSASTReport will take in a sarif file and output a GitLab SAST Report
func TransformToGLSASTReport(reader io.Reader, rootPath string) (*report.Report, error) {
	s := sarif{}

	jsonBytes, err := readerToBytes(reader)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(jsonBytes, &s)
	if err != nil {
		return nil, err
	}

	if s.Version != "2.1.0" {
		return nil, fmt.Errorf("version for SARIF is %s, but we only support 2.1.0", s.Version)
	}

	var allVulns []report.Vulnerability

	// It is generally expected to only have a single run, but best to parse all as it is a collection.
	for _, run := range s.Runs {
		vulns, err := transformRun(run, rootPath)
		if err != nil {
			return nil, err
		}

		allVulns = append(allVulns, vulns...)
	}

	report := report.NewReport()
	report.Analyzer = metadata.AnalyzerID
	report.Config.Path = ruleset.PathSAST
	report.Vulnerabilities = allVulns
	return &report, nil
}

func readerToBytes(reader io.Reader) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(reader)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func transformRun(r run, rootPath string) ([]report.Vulnerability, error) {
	if r.Tool.Driver.Name != "semgrep" {
		return nil, fmt.Errorf("Driver is %s, but we only support semgrep", r.Tool.Driver.Name)
	}

	ruleMap := make(map[string]rule)
	for _, rule := range r.Tool.Driver.Rules {
		ruleMap[rule.ID] = rule
	}

	var vulns []report.Vulnerability
	for _, result := range r.Results {
		for _, location := range result.Locations {
			rule := ruleMap[result.RuleID]

			var description string
			if len(result.Message.Text) > vulnerabilityMessageMaxLength {
				description = result.Message.Text[:vulnerabilityMessageMaxLength]
			} else {
				description = result.Message.Text
			}

			lineEnd := location.PhysicalLocation.Region.EndLine
			if lineEnd == 0 {
				// https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317692 states that
				// EndLine defaults to StartLine
				lineEnd = location.PhysicalLocation.Region.StartLine
			}

			vulns = append(vulns, report.Vulnerability{
				Description: description,
				Category:    report.CategorySast,
				Message:     message(rule),
				Severity:    severity(rule),
				Scanner:     metadata.IssueScanner,
				Location: report.Location{
					File:      removeRootPath(location.PhysicalLocation.ArtifactLocation.URI, rootPath),
					LineStart: location.PhysicalLocation.Region.StartLine,
					LineEnd:   lineEnd,
				},
				Identifiers: identifiers(rule),
			})
		}
	}
	return vulns, nil
}

// See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html#_Toc34317855 for more
// information about the level property. The docs say that when level is not defined, then the value is equal
// to warning.
func severity(r rule) report.SeverityLevel {
	switch r.DefaultConfiguration.Level {
	case "error":
		return report.SeverityLevelCritical
	case "warning":
		return report.SeverityLevelMedium
	case "note":
		return report.SeverityLevelInfo
	case "none":
		return report.SeverityLevelUnknown
	default:
		return report.SeverityLevelMedium
	}
}

func message(r rule) string {
	for _, tag := range r.Properties.Tags {
		splits := strings.Split(tag, ":")
		if strings.HasPrefix(splits[0], "CWE") {
			return strings.TrimLeft(splits[1], " ")
		}
	}

	// default to full text description
	return r.FullDescription.Text
}

func identifiers(r rule) []report.Identifier {
	ids := []report.Identifier{
		{
			Type:  "semgrep_id",
			Name:  r.ID,
			Value: r.ID,
			URL: r.HelpURI,
		},
	}

	for _, tag := range r.Properties.Tags {
		matches := tagIDRegex.FindStringSubmatch(tag)

		if matches != nil {
			switch strings.ToLower(matches[1]) {
			case "cwe":
				cweID, err := strconv.Atoi(matches[2])
				if err != nil {
					log.Errorf("Failure to parse CWE ID: %v\n", err)
					continue
				}

				ids = append(ids, report.CWEIdentifier(cweID))
			default:
				ids = append(ids, report.Identifier{
					Type:  report.IdentifierType(strings.ToLower(matches[1])),
					Name:  matches[3],
					Value: matches[2],
				})
			}
		}
	}

	return ids
}

func removeRootPath(path, rootPath string) string {
	prefix := strings.TrimSuffix(rootPath, "/") + "/"
	return strings.TrimPrefix(path, prefix)
}
