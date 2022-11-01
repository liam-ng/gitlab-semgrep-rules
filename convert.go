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

	sastReport, err := report.TransformToGLSASTReport(reader, root, metadata.AnalyzerID, metadata.IssueScanner)
	if err != nil {
		return nil, err
	}

	for i := range sastReport.Vulnerabilities {
		vuln := &sastReport.Vulnerabilities[i]
		vuln.CompareKey = computeCompareKey(*vuln)
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
		if len(subrules) != 1 {
			return empty
		}
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

// generateScsID transforms the input ID into the original format produced by the
// Security Code Scan analyzer. For example, SCS0005-1 -> SCS0005.
func generateScsID(id string) report.Identifier {
	value := strings.Split(id, "-")[0]
	return report.Identifier{
		Type:  "security_code_scan_rule_id",
		Name:  value,
		Value: value,
	}
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

func generateFindSecBugsID(id string) report.Identifier {
	value := strings.Split(id, "-")[0]
	return report.Identifier{
		Type:  "find_sec_bugs_type",
		Name:  "Find Security Bugs-" + value,
		Value: value,
	}
}

func generateIDs(ruleIDs []string, generator func(string) report.Identifier) []report.Identifier {
	var ids []report.Identifier
	for i := 0; i < len(ruleIDs); i++ {
		ids = append(ids, generator(ruleIDs[i]))
	}
	return ids
}
