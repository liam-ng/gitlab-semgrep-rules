package metadata

import (
	"reflect"
	"testing"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v3"
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

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
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

	if !reflect.DeepEqual(want, got) {
		t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", want, got)
	}
}
