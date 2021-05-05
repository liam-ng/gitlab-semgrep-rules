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

// The nosec comments below are ignoring two false positive vulnerabilities. They are false positive as this
// program is built inside an environment (i.e. docker image) that we have full control over as well as the
// fact that we control the `projectPath` var passed into the function and accept the open file as an output.
// In other words, this function is internal to the complete program we're building and not exposed to any
// third party.
func analyze(c *cli.Context, projectPath string) (io.ReadCloser, error) {
	configPath := path.Join("/", "rules")
	outputPath := path.Join(projectPath, "semgrep.sarif")

	cmd := exec.Command("semgrep", "-f", configPath, "-o", outputPath, "--sarif", projectPath, "--no-rewrite-rule-ids", "--strict", "--no-git-ignore") // #nosec G204

	cmd.Dir = projectPath
	cmd.Env = os.Environ()

	output, _ := cmd.CombinedOutput()
	log.Debugf("%s\n%s", cmd.String(), output)

	return os.Open(outputPath) // #nosec G304
}
