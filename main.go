package main

import (
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"gitlab.com/gitlab-org/security-products/analyzers/command"
	"gitlab.com/gitlab-org/security-products/analyzers/common/v2/logutil"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/metadata"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/plugin"
)

func main() {
	app := cli.NewApp()
	app.Name = "analyzer"
	app.Version = metadata.AnalyzerVersion
	app.Authors = []*cli.Author{{Name: metadata.AnalyzerVendor}}
	app.Usage = metadata.AnalyzerUsage

	log.SetFormatter(&logutil.Formatter{Project: metadata.AnalyzerName})
	log.Info(metadata.AnalyzerUsage)

	app.Commands = command.NewCommands(command.Config{
		Match:        plugin.Match,
		Analyze:      analyze,
		AnalyzeFlags: analyzeFlags(),
		AnalyzeAll:   true,
		Convert:      convert,
		Scanner:      metadata.ReportScanner,
		ScanType:     metadata.Type,
	})

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
