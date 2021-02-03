package main

import (
	"io"
	"os"
	"os/exec"
	"path"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func analyzeFlags() []cli.Flag {
	return []cli.Flag{}
}

func analyze(c *cli.Context, projectPath string) (io.ReadCloser, error) {
	configPath := path.Join("/", "rules")
	outputPath := path.Join(projectPath, "semgrep.sarif")

	cmd := exec.Command("semgrep", "-f", configPath, "-o", outputPath, "--sarif", projectPath)
	cmd.Dir = projectPath
	cmd.Env = os.Environ()

	output, _ := cmd.CombinedOutput()
	log.Debugf("%s\n%s", cmd.String(), output)

	return os.Open(outputPath)
}
