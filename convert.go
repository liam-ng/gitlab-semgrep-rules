package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"

	log "github.com/sirupsen/logrus"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/metadata"
)

const (
	semgrepIdentifierIndex = 0
	semgrepIdentifier      = "semgrep_id"
)

type ruleFile struct {
	Rules []*ruleFileRule `yaml:"rules"`
}

type ruleFileRule struct {
	ID       string `yaml:"id"`
	Metadata *struct {
		PrimaryIdentifier    string `yaml:"primary_identifier"`
		SecondaryIdentifiers []*struct {
			Name  string                `yaml:"name"`
			Type  report.IdentifierType `yaml:"type"`
			Value string                `yaml:"value"`
		} `yaml:"secondary_identifiers"`
		Rest map[string]interface{} `yaml:"-"`
	} `yaml:"metadata"`
}

// ruleCache is used to extract rule-mappings from the meta-data provided by
// the rule files in sast-rules
var ruleCache = make(map[string]map[string]ruleFileRule)

func buildCache(src string) error {
	return filepath.Walk(src, func(fpath string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		if strings.HasSuffix(info.Name(), ".yml") {
			log.Debugf("adding %s to cache", info.Name())

			file := ruleFile{}

			name := strings.TrimSuffix(filepath.Base(info.Name()), ".yml")
			if _, ok := ruleCache[name]; !ok {
				ruleCache[name] = make(map[string]ruleFileRule)
			}

			yamlFile, err := ioutil.ReadFile(fpath)
			if err != nil {
				return fmt.Errorf("read rules for %s", info.Name())
			}
			err = yaml.Unmarshal(yamlFile, &file)
			if err != nil {
				return fmt.Errorf("read rules for %s", info.Name())
			}

			if file.Rules == nil {
				return fmt.Errorf("extract rules for %s", info.Name())
			}

			rules := file.Rules
			if rules == nil {
				return fmt.Errorf("extract rules for %s", info.Name())
			}

			log.Debugf("caching with key %s", name)

			for _, r := range rules {
				if r == nil || r.ID == "" {
					return fmt.Errorf("extract rules for %s", info.Name())
				}

				ruleCache[name][r.ID] = *r
			}
		}
		return nil
	})
}

func convert(reader io.Reader, prependPath string) (*report.Report, error) {
	// HACK: extract root path from environment variables
	// TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/320975
	root := os.Getenv("ANALYZER_TARGET_DIR")
	if root == "" {
		root = os.Getenv("CI_PROJECT_DIR")
	}

	src := os.Getenv(flagSASTSegrepRuleConfigDirEnv)
	if src == "" {
		return nil, fmt.Errorf("no rule configuration found")
	}

	// building up rule cache
	err := buildCache(src)
	if err != nil {
		return nil, err
	}

	log.Debugf("Converting report with the root path: %s", root)

	sastReport, err := report.TransformToGLSASTReport(reader, root, metadata.AnalyzerID, metadata.IssueScanner)
	if err != nil {
		return nil, err
	}

	return addAnalyzerIdentifiers(sastReport)
}

// addAnalyzerIdentifiers iterates through report vulnerability identifiers. Each identifier is then use to
// determine how the semgrep rule maps to a corresponding analyzer like bandit, or eslint.
func addAnalyzerIdentifiers(sastReport *report.Report) (*report.Report, error) {
	for index, vul := range sastReport.Vulnerabilities {
		ruleID := vul.Identifiers[semgrepIdentifierIndex].Value

		ids, err := ruleIDToIdentifier(ruleID, vul.Identifiers)
		if err != nil {
			return nil, err
		}

		if len(ids) > 0 {
			sastReport.Vulnerabilities[index].Identifiers = ids
		}
	}
	return sastReport, nil
}

func ruleIDToIdentifier(id string, vulnIDs []report.Identifier) ([]report.Identifier, error) {
	identifiers := []report.Identifier{}
	analyzer := ""

	// only accept the
	for k := range ruleCache {
		if strings.HasPrefix(id, k) {
			analyzer = k
		}
	}

	// only apply mappings to predefined analyzers
	// treat the native id as primary id for all other cases
	if analyzer == "" {
		identifiers = append(identifiers, report.Identifier{
			Type:  report.IdentifierType(semgrepIdentifier),
			Name:  id,
			Value: id,
		})
		return identifiers, nil
	}

	if _, ok := ruleCache[analyzer]; !ok {
		return nil, fmt.Errorf("No mappings for %s present", analyzer)
	}

	analyzerIDMappings := ruleCache[analyzer]
	if _, ok := analyzerIDMappings[id]; !ok {
		return nil, fmt.Errorf("Unmapped rule %s for %s", id, analyzer)
	}

	rule := analyzerIDMappings[id]

	if rule.Metadata == nil {
		return nil, fmt.Errorf("metadata not present for %s", id)
	}

	// primary identifier
	if rule.Metadata.PrimaryIdentifier == "" {
		log.Debugf("primary identifier not present for %s", id)
	}
	// some analyzers expect an appended `-x` to the name and value
	// which is needed for the primary identifier
	switch analyzer {
	case "gosec", "flawfinder", "security_code_scan", "find_sec_bugs":
		identifiers = append(identifiers, report.Identifier{
			Type:  semgrepIdentifier,
			Name:  id,
			Value: id,
		})
	default:
		identifiers = append(identifiers, report.Identifier{
			Type:  semgrepIdentifier,
			Name:  rule.Metadata.PrimaryIdentifier,
			Value: rule.Metadata.PrimaryIdentifier,
		})
	}

	// HACK: append metadata identifiers like cwe and owasp before `secondary identifiers`
	// this could probabaly be refactored to be built into the rule cache. Atm
	// `url` is not generated by sast-rules, so that might be something we add
	// later down the road
	for _, v := range vulnIDs {
		if v.Type == report.IdentifierTypeCWE || v.Type == "owasp" {
			identifiers = append(identifiers, v)
		}
	}

	// secondary identifier
	if len(rule.Metadata.SecondaryIdentifiers) == 0 {
		log.Debugf("secondary identifier not present for %s", id)
	}

	for _, secondaryIdentifier := range rule.Metadata.SecondaryIdentifiers {
		if secondaryIdentifier == nil {
			return nil, fmt.Errorf("load secondary identifier %s", id)
		}

		if secondaryIdentifier.Name == "" || secondaryIdentifier.Type == "" || secondaryIdentifier.Value == "" {
			return nil, fmt.Errorf("incomplete secondary identifier for %s", id)
		}

		// again, apply some special rules for secondary identifiers:
		switch analyzer {
		case "eslint":
			identifiers = append(identifiers, report.Identifier{
				Type: secondaryIdentifier.Type,
				// HACK: this should probably go into sast-rules
				Name:  strings.Replace(secondaryIdentifier.Name, "ESLint rule ID", "ESLint rule ID security", -1),
				Value: "security/" + secondaryIdentifier.Value,
			})
		default:
			identifiers = append(identifiers, report.Identifier{
				Type:  secondaryIdentifier.Type,
				Name:  secondaryIdentifier.Name,
				Value: secondaryIdentifier.Value,
			})
		}
	}

	return identifiers, nil
}
