package metadata

import (
	"fmt"
	"os"

	report "gitlab.com/gitlab-org/security-products/analyzers/report/v2"
)

const (
	// AnalyzerVendor is the vendor/maintainer of the analyzer
	AnalyzerVendor = "GitLab"

	// AnalyzerID identifies the analyzer
	AnalyzerID = scannerID

	// AnalyzerName is the name of the analyzer
	AnalyzerName = scannerName

	scannerVendor = AnalyzerVendor
	scannerURL    = "https://github.com/returntocorp/semgrep"

	// scannerID identifies the scanner that generated the report
	scannerID = "semgrep"

	// scannerName identifies the scanner that generated the report
	scannerName = "Semgrep"

	// Type returns the type of the scan
	Type report.Category = report.CategorySast
)

var (
	// AnalyzerVersion is a placeholder value which the Dockerfile will dynamically
	// overwrite at build time with the most recent version from the CHANGELOG.md file
	AnalyzerVersion = "not-configured"

	// ScannerVersion is the semantic version of the scanner and is defined in the Dockerfile
	ScannerVersion = os.Getenv("SCANNER_VERSION")

	// IssueScanner describes the scanner used to find a vulnerability
	IssueScanner = report.Scanner{
		ID:   scannerID,
		Name: scannerName,
	}

	// ReportScanner returns identifying information about a security scanner
	ReportScanner = report.ScannerDetails{
		ID:      scannerID,
		Name:    scannerName,
		Version: ScannerVersion,
		Vendor: report.Vendor{
			Name: scannerVendor,
		},
		URL: scannerURL,
	}

	// AnalyzerUsage provides a one line usage string for the analyzer
	AnalyzerUsage = fmt.Sprintf("%s %s analyzer v%s", AnalyzerVendor, AnalyzerName, AnalyzerVersion)
)
