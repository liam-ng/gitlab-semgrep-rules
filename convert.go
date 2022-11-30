package main

import (
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
	"gitlab.com/gitlab-org/security-products/analyzers/ruleset"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/metadata"
)

const semgrepIdentifierIndex = 0

// computeCompareKey returns a stable and unique key based on some content of the
// vulnerability. The value is intended to be used as the `cve` field temporarily,
// until analyzers are able to be upgraded to v15.x of the Security Report schema.
//
// See https://gitlab.com/gitlab-org/gitlab/-/issues/374496#note_1148831158
func computeCompareKey(v report.Vulnerability) string {
	return strings.Join(
		[]string{
			string(v.Identifiers[0].Type),
			v.Identifiers[0].Value,
			fmt.Sprint(v.Location.LineStart),
			fmt.Sprint(v.Location.LineEnd),
		}, ":")
}

func convert(reader io.Reader, prependPath string) (*report.Report, error) {
	// HACK: extract root path from environment variables
	// TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/320975
	root := os.Getenv("ANALYZER_TARGET_DIR")
	if root == "" {
		root = os.Getenv("CI_PROJECT_DIR")
	}

	log.Debugf("Converting report with the root path: %s", root)

	// Load custom config if available
	rulesetPath := filepath.Join(prependPath, ruleset.PathSAST)
	rulesetConfig, err := ruleset.Load(rulesetPath, "semgrep")
	if err != nil {
		switch err.(type) {
		case *ruleset.NotEnabledError:
			log.Debug(err)
		case *ruleset.ConfigFileNotFoundError:
			log.Debug(err)
		case *ruleset.ConfigNotFoundError:
			log.Debug(err)
		case *ruleset.InvalidConfig:
			log.Fatal(err)
		default:
			return nil, err
		}
	}

	configPath, err := getConfigPath(prependPath, rulesetConfig)
	if err != nil {
		return nil, err
	}

	sastReport, err := report.TransformToGLSASTReport(reader, root, metadata.AnalyzerID, metadata.IssueScanner)
	if err != nil {
		return nil, err
	}

	for i := range sastReport.Vulnerabilities {
		vuln := &sastReport.Vulnerabilities[i]
		vuln.CompareKey = computeCompareKey(*vuln)
	}

	return addAnalyzerIdentifiers(sastReport, configPath)
}

// addAnalyzerIdentifiers iterates through report vulnerability identifiers. Each identifier is then use to
// determine how the semgrep rule maps to a corresponding analyzer like bandit, or eslint.
func addAnalyzerIdentifiers(sastReport *report.Report, configPath string) (*report.Report, error) {
	ruleMap, err := buildRuleMap(configPath)
	if err != nil {
		return sastReport, err
	}

	for index, vul := range sastReport.Vulnerabilities {
		ruleID := vul.Identifiers[semgrepIdentifierIndex].Value

		pID, sIDs := ruleToIDs(ruleID, ruleMap)
		if pID != nil {
			sastReport.Vulnerabilities[index].Identifiers[0] = *pID
		}
		if len(sIDs) > 0 {
			sastReport.Vulnerabilities[index].Identifiers = append(vul.Identifiers, sIDs...)
		}
	}
	return sastReport, nil
}

// ruleToIDs will take in ruleID as string and output a trimmed primary identifier
// and slice of secondary identifiers containing each sub-rule.
// Examples of secondary identifiers: bandit.B303-1 (outputs one identifier), bandit.B502.B503 (outputs two identifiers)
func ruleToIDs(ruleID string, ruleMap map[string]semgrepRuleFile) (*report.Identifier, []report.Identifier) {
	var empty []report.Identifier
	matches := strings.Split(ruleID, ".")
	if len(matches) < 2 {
		return &report.Identifier{}, empty
	}

	analyzer := strings.ToLower(matches[0])

	switch analyzer {
	case "bandit", "eslint", "find_sec_bugs", "flawfinder", "gosec", "security_code_scan":
		if len(ruleMap[analyzer].Rules) == 0 {
			return &report.Identifier{}, empty
		}

		rule := findRuleForID(ruleID, ruleMap[analyzer])
		if rule == nil {
			return &report.Identifier{}, empty
		}

		return buildPrimaryID(ruleID, rule, analyzer), buildSecondaryIDs(rule)
	default:
		return &report.Identifier{}, empty
	}
}

func buildPrimaryID(ruleID string, rule *semgrepRule, analyzer string) *report.Identifier {
	ID := report.Identifier{
		Type: report.IdentifierType("semgrep_id"),
	}
	switch analyzer {
	case "gosec", "flawfinder", "security_code_scan", "find_sec_bugs":
		ID.Name = ruleID
		ID.Value = ruleID
	default:
		ID.Name = rule.Metadata.PrimaryIdentifier
		ID.Value = rule.Metadata.PrimaryIdentifier
	}

	// generate and add a URL to the semgrep ID
	if strings.HasPrefix(ruleID, "bandit") || strings.HasPrefix(ruleID, "eslint") {
		ID.URL = fmt.Sprintf("https://semgrep.dev/r/gitlab.%s",
			rule.Metadata.PrimaryIdentifier)
	}

	return &ID
}

func buildSecondaryIDs(rule *semgrepRule) []report.Identifier {
	identifiers := []report.Identifier{}

	for _, sid := range rule.Metadata.SecondaryIdentifiers {
		if sid.Type == "eslint_rule_id" {
			sid.Name = strings.Replace(sid.Name, "ESLint rule ID", "ESLint rule ID security", -1)
			sid.Value = "security/" + sid.Value
		}

		identifiers = append(
			identifiers,
			report.Identifier{
				Type:  report.IdentifierType(sid.Type),
				Name:  sid.Name,
				Value: sid.Value,
			})
	}

	return identifiers
}

func findRuleForID(id string, ruleFile semgrepRuleFile) *semgrepRule {
	for _, rule := range ruleFile.Rules {
		if rule.ID == id {
			return &rule
		}
	}

	return nil
}

func buildRuleMap(configPath string) (map[string]semgrepRuleFile, error) {
	ruleMap := map[string]semgrepRuleFile{}

	err := filepath.WalkDir(configPath, func(path string, d fs.DirEntry, err error) error {
		_, err = os.Stat(path)
		if err != nil || d.IsDir() {
			return nil
		}

		var ruleFile semgrepRuleFile

		fileContent, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read rule file at %s: %w", path, err)
		}

		if err = yaml.Unmarshal(fileContent, &ruleFile); err != nil {
			return fmt.Errorf("parse rule file at %s: %w", path, err)
		}

		rulesetFile := strings.Split(filepath.Base(path), ".")[0]
		ruleMap[rulesetFile] = ruleFile

		return nil
	})

	return ruleMap, err
}
