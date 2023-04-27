package metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v4"
)

func TestAnalyzerDetails(t *testing.T) {
	want := report.AnalyzerDetails{
		ID:      "semgrep",
		Name:    "Semgrep",
		Version: AnalyzerVersion,
		Vendor: report.Vendor{
			Name: "GitLab",
		},
		URL: "https://gitlab.com/gitlab-org/security-products/analyzers/semgrep",
	}
	got := AnalyzerDetails

	assert.Equal(t, want, got)
}

func TestReportScanner(t *testing.T) {
	want := report.ScannerDetails{
		ID:      "semgrep",
		Name:    "Semgrep",
		Version: ScannerVersion,
		Vendor: report.Vendor{
			Name: "GitLab",
		},
		URL: "https://github.com/returntocorp/semgrep",
	}
	got := ReportScanner

	assert.Equal(t, want, got)
}
