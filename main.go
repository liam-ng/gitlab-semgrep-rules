package main

import (
	"os"

	log "github.com/sirupsen/logrus"

	"gitlab.com/gitlab-org/security-products/analyzers/command/v2"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v3/cacert"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/metadata"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/plugin"
)

func main() {
	app := command.NewApp(metadata.AnalyzerDetails)
	app.Version = metadata.AnalyzerVersion
	app.Commands = command.NewCommands(command.Config{
		Match:        plugin.Match,
		Analyze:      analyze,
		AnalyzeFlags: analyzeFlags(),
		AnalyzeAll:   true,
		Convert:      convert,
		Analyzer:     metadata.AnalyzerDetails,
		Scanner:      metadata.ReportScanner,
		ScanType:     metadata.Type,
		CACertImportOptions: cacert.ImportOptions{
			Path: customCertPath(),
		},
	})

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// customCertPath returns custom certificate's file path into which user's certificate
// content can be written.
func customCertPath() string {
	if cacert.IsUBIImage() {
		return "/usr/share/pki/ca-trust-source/anchors/ca-certificates.crt"
	}
	return "/etc/ssl/certs/ca-certificates.crt"
}
