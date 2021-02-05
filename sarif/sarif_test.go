package sarif

import (
	"os"
	"reflect"
	"testing"

	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/issue"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/ruleset"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/metadata"
)

func TestTransformToGLSASTReport(t *testing.T) {
	fixture, err := os.Open("test_fixtures/semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}

	scanner := metadata.IssueScanner
	want := &issue.Report{
		Version:         issue.CurrentVersion(),
		Analyzer:        "semgrep",
		Config:          ruleset.Config{Path: ruleset.PathSAST},
		DependencyFiles: []issue.DependencyFile{},
		Remediations:    []issue.Remediation{},
		Vulnerabilities: []issue.Issue{
			{
				Category: issue.CategorySast,
				Message:  "Detected MD5 hash algorithm which is considered insecure. MD5 is not\ncollision resistant and is therefore not suitable as a cryptographic\nsignature. Use SHA256 or SHA3 instead.\n",
				Severity: issue.SeverityLevelMedium,
				Scanner:  scanner,
				Location: issue.Location{
					File:      "app/app.py",
					LineStart: 141,
					LineEnd:   141,
				},
				Identifiers: []issue.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5",
						Value: "rules.python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5",
					},
					{
						Type:  issue.IdentifierTypeCWE,
						Name:  "327",
						Value: "Use of a Broken or Risky Cryptographic Algorithm",
					},
					{
						Type:  "owasp",
						Name:  "A3",
						Value: "Sensitive Data Exposure",
					},
				},
			},
			{
				Category: issue.CategorySast,
				Message:  "Certificate verification has been explicitly disabled. This\npermits insecure connections to insecure servers. Re-enable\ncertification validation.\n",
				Severity: issue.SeverityLevelCritical,
				Scanner:  scanner,
				Location: issue.Location{
					File:      "tests/e2e_zap.py",
					LineStart: 17,
					LineEnd:   18,
				},
				Identifiers: []issue.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
						Value: "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
					},
					{
						Type:  issue.IdentifierTypeCWE,
						Name:  "295",
						Value: "Improper Certificate Validation",
					},
					{
						Type:  "owasp",
						Name:  "A3",
						Value: "Sensitive Data Exposure",
					},
				},
			},
			{
				Category: issue.CategorySast,
				Message:  "Certificate verification has been explicitly disabled. This\npermits insecure connections to insecure servers. Re-enable\ncertification validation.\n",
				Severity: issue.SeverityLevelCritical,
				Scanner:  scanner,
				Location: issue.Location{
					File:      "tests/e2e_zap.py",
					LineStart: 28,
					LineEnd:   29,
				},
				Identifiers: []issue.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
						Value: "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
					},
					{
						Type:  issue.IdentifierTypeCWE,
						Name:  "295",
						Value: "Improper Certificate Validation",
					},
					{
						Type:  "owasp",
						Name:  "A3",
						Value: "Sensitive Data Exposure",
					},
				},
			},
		},
	}

	// TODO double check that prependPath includes the trailing slash
	got, err := TransformToGLSASTReport(fixture, "/tmp/app/")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}
