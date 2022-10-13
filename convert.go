package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/metadata"
)

const semgrepIdentifierIndex = 0

func convert(reader io.Reader, prependPath string) (*report.Report, error) {
	// HACK: extract root path from environment variables
	// TODO: https://gitlab.com/gitlab-org/gitlab/-/issues/320975
	root := os.Getenv("ANALYZER_TARGET_DIR")
	if root == "" {
		root = os.Getenv("CI_PROJECT_DIR")
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

		// generate and add a URL to the semgrep ID
		if strings.HasPrefix(ruleID, "bandit") || strings.HasPrefix(ruleID, "eslint") {
			vul.Identifiers[semgrepIdentifierIndex].URL = fmt.Sprintf("https://semgrep.dev/r/gitlab.%s", ruleID)
		}

		ids := ruleToIDs(ruleID)
		if len(ids) > 0 {
			sastReport.Vulnerabilities[index].Identifiers = append(vul.Identifiers, ids...)
		}
	}
	return sastReport, nil
}

// ruleToIDs will take in ruleID as string and output a slice of identifiers containing each sub-rule.
// Examples of ruleID: bandit.B303-1 (outputs one identifier), bandit.B502.B503 (outputs two identifiers)
func ruleToIDs(ruleID string) []report.Identifier {
	var empty []report.Identifier
	matches := strings.Split(ruleID, ".")
	if len(matches) < 2 {
		return empty
	}

	analyzer, subrules := strings.ToLower(matches[0]), matches[1:]

	switch analyzer {
	case "security_code_scan":
		return generateIDs(subrules, generateScsID)
	case "bandit":
		return generateIDs(subrules, generateBanditID)
	case "eslint":
		return generateIDs(subrules, generateEslintID)
	case "flawfinder":
		return generateIDs(subrules, generateFlawfinderID)
	case "gosec":
		return generateIDs(subrules, generateGosecID)
	case "find_sec_bugs":
		return generateIDs(subrules, generateFindSecBugsID)
	default:
		return empty
	}
}

// computeRuleName converts a Semgrep rule name to its native rule ID by removing any numbered suffixes
// and joining any remaining parts with dashes.
// For example: B101-1 returns B101, and security/detect-non-literal-regexp-1 -> security/detect-non-literal-regexp
func computeRuleName(id string) (string, error) {
	segments := strings.Split(id, "-")
	if len(segments) == 1 {
		return segments[0], nil
	}

	if len(segments) < 2 {
		return "", fmt.Errorf("Unable to compute native rule id from '%s'", id)
	}

	return strings.Join(segments[0:len(segments)-1], "-"), nil
}

func generateID(id string, typ string, name string, sep string) (report.Identifier, error) {
	value, err := computeRuleName(id)
	if err != nil {
		return report.Identifier{}, err
	}

	return report.Identifier{
		Type:  report.IdentifierType(typ),
		Name:  strings.Join([]string{name, value}, sep),
		Value: value,
	}, nil
}

// generateScsID transforms the input ID into the original format produced by the
// Security Code Scan analyzer. For example, SCS0005-1 -> SCS0005.
func generateScsID(id string) (report.Identifier, error) {
	return generateID(id, "security_code_scan_rule_id", "", "")
}

// generateBanditID will take in bandit_id as string and output an identifier
// Examples of bandit_id: B303-1, B305
func generateBanditID(id string) (report.Identifier, error) {
	value := strings.Split(id, "-")[0]
	return report.Identifier{
		Type:  "bandit_test_id",
		Name:  "Bandit Test ID " + value,
		Value: value,
	}, nil
}

func generateEslintID(id string) (report.Identifier, error) {
	return report.Identifier{
		Type:  "eslint_rule_id",
		Name:  "ESLint rule ID security/" + id,
		Value: "security/" + id,
	}, nil
}

func generateFlawfinderID(id string) (report.Identifier, error) {
	return generateID(id, "flawfinder_func_name", "Flawfinder -", " ")
}

func generateGosecID(id string) (report.Identifier, error) {
	return generateID(id, "gosec_rule_id", "Gosec Rule ID", " ")
}

func generateFindSecBugsID(id string) (report.Identifier, error) {
	return generateID(id, "find_sec_bugs_type", "Find Security Bugs-", "")
}

func generateIDs(ruleIDs []string, generator func(string) (report.Identifier, error)) []report.Identifier {
	var ids []report.Identifier
	for i := 0; i < len(ruleIDs); i++ {
		ruleid, err := generator(ruleIDs[i])
		if err != nil {
			log.Error(err)
			continue
		}

		ids = append(ids, ruleid)
	}
	return ids
}
