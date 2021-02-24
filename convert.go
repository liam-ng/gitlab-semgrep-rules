package main

import (
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v2"
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

func addAnalyzerIdentifiers(sastReport *report.Report) (*report.Report, error) {
	for index, vul := range sastReport.Vulnerabilities {
		ruleID := vul.Identifiers[semgrepIdentifierIndex].Value

		banditIdentifiers := banditIdentifiersFor(ruleID)
		if len(banditIdentifiers) > 0 {
			sastReport.Vulnerabilities[index].Identifiers = append(vul.Identifiers, banditIdentifiers...)
		}

	}
	return sastReport, nil
}

//  banditIdentifiersFor will take in ruleID as string and output a slice of identifiers
//  Examples of ruleID: rules.bandit.B303-1, rules.bandit.B502.B503
func banditIdentifiersFor(ruleID string) []report.Identifier {
	matches := strings.Split(ruleID, ".")
	var ids []report.Identifier

	if len(matches) < 3 {
		return []report.Identifier{}
	}

	if matches[1] == "bandit" {
		for i := 2; i < len(matches); i++ {
			ids = append(ids, generateBanditID(matches[i]))
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
