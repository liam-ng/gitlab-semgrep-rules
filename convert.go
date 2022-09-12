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

// banditIdentifiersFor will take in ruleID as string and output a slice of identifiers
// Examples of ruleID: bandit.B303-1, bandit.B502.B503
func ruleToIDs(ruleID string) []report.Identifier {
	var empty []report.Identifier
	matches := strings.Split(ruleID, ".")
	if len(matches) < 2 {
		return empty
	}

	analyzer, subrules := strings.ToLower(matches[0]), matches[1:]

	fmt.Println(subrules)
	fmt.Println(analyzer)
	switch analyzer {
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

// compute Rule name computes the native rule id from a semgrep rule
// it removes numbered suffixes separated by `-` and joins the remaining
// prefix some-rule-2 => some-rule
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
	fmt.Printf("id %s\n", id)
	fmt.Printf("rul %s\n", value)
	if err != nil {
		return report.Identifier{}, err
	}

	return report.Identifier{
		Type:  report.IdentifierType(typ),
		Name:  strings.Join([]string{name, value}, sep),
		Value: value,
	}, nil
}

// generateBanditID will take in bandit_id as string and output an identifier
// Examples of bandit_id: B303-1, B305
func generateBanditID(id string) (report.Identifier, error) {
	return generateID(id, "bandit_test_id", "Bandit Test ID", " ")
}

func generateEslintID(id string) (report.Identifier, error) {
	return generateID(id, "eslint_rule_id", "ESLint rule ID", " ")
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
