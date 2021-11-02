package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/sarif"
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

	sastReport, err := sarif.TransformToGLSASTReport(reader, root)
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

//  banditIdentifiersFor will take in ruleID as string and output a slice of identifiers
//  Examples of ruleID: bandit.B303-1, bandit.B502.B503
func ruleToIDs(ruleID string) []report.Identifier {
	matches := strings.Split(ruleID, ".")
	var ids []report.Identifier

	if len(matches) < 2 {
		return []report.Identifier{}
	}

	if matches[0] == "bandit" {
		for i := 1; i < len(matches); i++ {
			ids = append(ids, generateBanditID(matches[i]))
		}
	}

	if matches[0] == "eslint" && len(matches) == 2 {
		ids = append(ids, generateEslintID(matches[1]))
	}

	if matches[0] == "flawfinder" {
		for i := 1; i < len(matches); i++ {
			ids = append(ids, generateFlawfinderID(matches[i]))
		}
	}

	if matches[0] == "gosec" {
		for i := 1; i < len(matches); i++ {
			ids = append(ids, generateGosecID(matches[i]))
		}
	}

	return ids
}

//  generateBanditID will take in bandit_id as string and output an identifier
//  Examples of bandit_id: B303-1, B305
func generateBanditID(id string) report.Identifier {
	value := strings.Split(id, "-")[0]
	return report.Identifier{
		Type:  "bandit_test_id",
		Name:  "Bandit Test ID " + value,
		Value: value,
	}
}

func generateEslintID(id string) report.Identifier {
	return report.Identifier{
		Type:  "eslint_rule_id",
		Name:  "ESLint rule ID security/" + id,
		Value: "security/" + id,
	}
}

func generateFlawfinderID(id string) report.Identifier {
	value := strings.Split(id, "-")[0]
	return report.Identifier{
		Type:  "flawfinder_func_name",
		Name:  "Flawfinder - " + value,
		Value: value,
	}
}

func generateGosecID(id string) report.Identifier {
	value := strings.Split(id, "-")[0]
	return report.Identifier{
		Type:  "gosec_rule_id",
		Name:  "Gosec Rule ID " + value,
		Value: value,
	}
}
