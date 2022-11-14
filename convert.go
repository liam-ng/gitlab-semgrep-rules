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

// ruleCache is used to extract rule-mappings from the meta-data provided by
// the rule files in sast-rules
var ruleCache = make(map[string]map[string]interface{})

func buildCache(src string) error {
	return filepath.Walk(src, func(fpath string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		if strings.HasSuffix(info.Name(), ".yml") {
			log.Debugf("adding %s to cache", info.Name())
			rules := make(map[string]interface{})

			name := strings.TrimSuffix(filepath.Base(info.Name()), ".yml")

			yamlFile, err := ioutil.ReadFile(fpath)
			if err != nil {
				return err
			}
			err = yaml.Unmarshal(yamlFile, rules)
			if err != nil {
				return err
			}

			if _, ok := rules["rules"]; !ok {
				return fmt.Errorf("Unable to extract rules for %s", info.Name())
			}

			rulearray := rules["rules"].([]interface{})
			if rulearray == nil {
				return fmt.Errorf("Unable to extract rules for %s", info.Name())
			}

			log.Debugf("caching with key %s", name)
			rulemap := make(map[string]interface{})
			for i := range rulearray {
				rule := rulearray[i].(map[interface{}]interface{})
				if rule == nil {
					return fmt.Errorf("Unable to extract rules for %s", info.Name())
				}
				if _, ok := rule["id"]; !ok {
					return fmt.Errorf("Unable to extract rules for %s", info.Name())
				}
				rulemap[rule["id"].(string)] = rule
			}

			ruleCache[name] = rulemap
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

		ids, err := ruleIDToIdentifier(ruleID)
		if err != nil {
			return nil, err
		}
		if len(ids) > 0 {
			sastReport.Vulnerabilities[index].Identifiers = ids
		}
	}
	return sastReport, nil
}

func ruleIDToIdentifier(id string) ([]report.Identifier, error) {
	log.Info("\n\n\n\nid: ", id)
	identifiers := []report.Identifier{}
	analyzer := ""

	// only accept the
	for k := range ruleCache {
		if strings.HasPrefix(id, k) {
			analyzer = k
		}
	}
	log.Info("analyzer: ", analyzer)

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

	rule := analyzerIDMappings[id].(map[interface{}]interface{})
	if rule == nil {
		return nil, fmt.Errorf("Error loading rule content for %s", id)
	}

	if _, ok := rule["metadata"]; !ok {
		return nil, fmt.Errorf("metadata not present for %s", id)
	}

	metadata := rule["metadata"].(map[interface{}]interface{})
	if metadata == nil {
		return nil, fmt.Errorf("Error loading metadata for %s", id)
	}

	if _, ok := metadata["primary_identifier"]; !ok {
		return nil, fmt.Errorf("primary identifier not present for %s", id)
	}

	primaryIdentifierStr := metadata["primary_identifier"].(string)

	// some analyzers expect an appended `-x` to the name and value
	// which is needed for the primary identifier
	switch analyzer {
	case "gosec", "flawfinder":
		identifiers = append(identifiers, report.Identifier{
			Type:  report.IdentifierType(semgrepIdentifier),
			Name:  id,
			Value: id,
		})
	default:
		identifiers = append(identifiers, report.Identifier{
			Type:  report.IdentifierType(semgrepIdentifier),
			Name:  primaryIdentifierStr,
			Value: primaryIdentifierStr,
		})
	}

	if _, ok := metadata["secondary_identifiers"]; !ok {
		return nil, fmt.Errorf("secondary identifier not present for %s", id)
	}

	secondaryIdentifier := metadata["secondary_identifiers"].([]interface{})
	if secondaryIdentifier == nil {
		return nil, fmt.Errorf("Error loading metadata for %s", id)
	}

	for i := range secondaryIdentifier {
		secondaryIdentifier := secondaryIdentifier[i].(map[interface{}]interface{})
		if secondaryIdentifier == nil {
			return nil, fmt.Errorf("Error loading secondary identifier %s", id)
		}

		name, nameok := secondaryIdentifier["name"].(string)
		typ, typeok := secondaryIdentifier["type"].(string)
		value, valueok := secondaryIdentifier["value"].(string)

		if !nameok || !typeok || !valueok {
			return nil, fmt.Errorf("incomplete secondary identifier for %s", id)
		}

		// again, apply some special rules for secondary identifiers:
		switch analyzer {
		case "eslint":
			identifiers = append(identifiers, report.Identifier{
				Type:  report.IdentifierType(typ),
				Name:  name,
				Value: "security/" + value,
			})
		default:
			identifiers = append(identifiers, report.Identifier{
				Type:  report.IdentifierType(typ),
				Name:  name,
				Value: value,
			})
		}
	}
	return identifiers, nil
}
