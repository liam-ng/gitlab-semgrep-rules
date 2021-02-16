package sarif

import (
	"os"
	"reflect"
	"testing"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v2"
	"gitlab.com/gitlab-org/security-products/analyzers/ruleset"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/metadata"
)

func TestTransformToGLSASTReport(t *testing.T) {
	fixture, err := os.Open("test_fixtures/semgrep.sarif")
	if err != nil {
		t.Fatal(err)
	}

	scanner := metadata.IssueScanner
	longMessage := "Very Long Message: Detected MD5 hash algorithm which is considered insecure. MD5 is not\ncollision resistant and is therefore not suitable as a cryptographic\nsignature. Use SHA256 or SHA3 instead.\n Detected MD5 hash algorithm which is considered insecure. MD5 is not\ncollision resistant and is therefore not suitable as a cryptographic\nsignature. Use SHA256 or SHA3 instead.\n Detected MD5 hash algorithm which is considered insecure. MD5 is not\ncollision resistant and is therefore not suitable as a cryptographic\nsignature. Use SHA256 or SHA3 instead.\n"
	truncatedMessage := longMessage[:vulnerabilityMessageMaxLength]

	want := &report.Report{
		Version:         report.CurrentVersion(),
		Analyzer:        "semgrep",
		Config:          ruleset.Config{Path: ruleset.PathSAST},
		DependencyFiles: []report.DependencyFile{},
		Remediations:    []report.Remediation{},
		Vulnerabilities: []report.Vulnerability{
			{
				Category: report.CategorySast,
				Message:  truncatedMessage,
				Severity: report.SeverityLevelMedium,
				Scanner:  scanner,
				Location: report.Location{
					File:      "app/app.py",
					LineStart: 141,
					LineEnd:   141,
				},
				Identifiers: []report.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5",
						Value: "rules.python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5",
					},
					{
						Type:  "cwe",
						Name:  "CWE-327",
						Value: "327",
						URL:   "https://cwe.mitre.org/data/definitions/327.html",
					},
					{
						Type:  "owasp",
						Name:  "Sensitive Data Exposure",
						Value: "A3",
					},
				},
			},
			{
				Category: report.CategorySast,
				Message:  "Certificate verification has been explicitly disabled. This\npermits insecure connections to insecure servers. Re-enable\ncertification validation.\n",
				Severity: report.SeverityLevelCritical,
				Scanner:  scanner,
				Location: report.Location{
					File:      "tests/e2e_zap.py",
					LineStart: 17,
					LineEnd:   18,
				},
				Identifiers: []report.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
						Value: "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
					},
					{
						Type:  "cwe",
						Name:  "CWE-295",
						Value: "295",
						URL:   "https://cwe.mitre.org/data/definitions/295.html",
					},
					{
						Type:  "owasp",
						Name:  "Sensitive Data Exposure",
						Value: "A3",
					},
				},
			},
			{
				Category: report.CategorySast,
				Message:  "Certificate verification has been explicitly disabled. This\npermits insecure connections to insecure servers. Re-enable\ncertification validation.\n",
				Severity: report.SeverityLevelCritical,
				Scanner:  scanner,
				Location: report.Location{
					File:      "tests/e2e_zap.py",
					LineStart: 28,
					LineEnd:   29,
				},
				Identifiers: []report.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
						Value: "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
					},
					{
						Type:  "cwe",
						Name:  "CWE-295",
						Value: "295",
						URL:   "https://cwe.mitre.org/data/definitions/295.html",
					},
					{
						Type:  "owasp",
						Name:  "Sensitive Data Exposure",
						Value: "A3",
					},
				},
			},
			{
				Category: report.CategorySast,
				Message:  "Detected MD5 hash algorithm which is considered insecure. MD5 is not\ncollision resistant and is therefore not suitable as a cryptographic\nsignature. Use SHA256 or SHA3 instead.\n",
				Severity: report.SeverityLevelMedium,
				Scanner:  scanner,
				Location: report.Location{
					File:      "app/app.py",
					LineStart: 141,
					LineEnd:   141,
				},
				Identifiers: []report.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5",
						Value: "rules.python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-md5",
					},
					{
						Type:  "cwe",
						Name:  "CWE-327",
						Value: "327",
						URL:   "https://cwe.mitre.org/data/definitions/327.html",
					},
					{
						Type:  "owasp",
						Name:  "Sensitive Data Exposure",
						Value: "A3",
					},
				},
			},
			{
				Category: report.CategorySast,
				Message:  "Certificate verification has been explicitly disabled. This\npermits insecure connections to insecure servers. Re-enable\ncertification validation.\n",
				Severity: report.SeverityLevelCritical,
				Scanner:  scanner,
				Location: report.Location{
					File:      "tests/e2e_zap.py",
					LineStart: 17,
					LineEnd:   18,
				},
				Identifiers: []report.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
						Value: "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
					},
					{
						Type:  "cwe",
						Name:  "CWE-295",
						Value: "295",
						URL:   "https://cwe.mitre.org/data/definitions/295.html",
					},
					{
						Type:  "owasp",
						Name:  "Sensitive Data Exposure",
						Value: "A3",
					},
				},
			},
			{
				Category: report.CategorySast,
				Message:  "Certificate verification has been explicitly disabled. This\npermits insecure connections to insecure servers. Re-enable\ncertification validation.\n",
				Severity: report.SeverityLevelCritical,
				Scanner:  scanner,
				Location: report.Location{
					File:      "tests/e2e_zap.py",
					LineStart: 28,
					LineEnd:   29,
				},
				Identifiers: []report.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
						Value: "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
					},
					{
						Type:  "cwe",
						Name:  "CWE-295",
						Value: "295",
						URL:   "https://cwe.mitre.org/data/definitions/295.html",
					},
					{
						Type:  "owasp",
						Name:  "Sensitive Data Exposure",
						Value: "A3",
					},
				},
			},
			{
				Category: report.CategorySast,
				Message:  "Certificate verification has been explicitly disabled. This\npermits insecure connections to insecure servers. Re-enable\ncertification validation.\n",
				Severity: report.SeverityLevelCritical,
				Scanner:  scanner,
				Location: report.Location{
					File:      "tests/e2e_zap.py",
					LineStart: 28,
					LineEnd:   29,
				},
				Identifiers: []report.Identifier{
					{
						Type:  "semgrep_id",
						Name:  "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
						Value: "rules.python.requests.security.disabled-cert-validation.disabled-cert-validation",
					},
					{
						Type:  "cwe",
						Name:  "CWE-295",
						Value: "295",
						URL:   "https://cwe.mitre.org/data/definitions/295.html",
					},
					{
						Type:  "owasp",
						Name:  "Sensitive Data Exposure",
						Value: "A3",
					},
				},
			},
		},
	}

	got, err := TransformToGLSASTReport(fixture, "/tmp/app/")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}

func TestRemoveRootPath(t *testing.T) {
	tests := []struct {
		path     string
		rootPath string
		expected string
	}{
		{"/a/b/c/d.foo", "/a/b/", "c/d.foo"},
		{"/a/b/c/d.foo", "/a/b", "c/d.foo"},
		{"/a/b/c/d.foo", "/a/c", "/a/b/c/d.foo"},
	}

	for _, tt := range tests {
		got := removeRootPath(tt.path, tt.rootPath)

		if got != tt.expected {
			t.Errorf("expected: %s, but got: %s", tt.expected, got)
		}
	}
}
