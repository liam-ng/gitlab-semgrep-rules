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

// The nosec comments below are safe as the caller of this function is part of the trusted common framework.
// We trust that the projectPath variable is safe to pass to a command as well as use to create a path to open
// for the io.ReadCloser that needs to be returned.
func analyze(c *cli.Context, projectPath string) (io.ReadCloser, error) {
	configPath := path.Join("/", "rules")
	outputPath := path.Join(projectPath, "semgrep.sarif")

	cmd := exec.Command("semgrep", "-f", configPath, "-o", outputPath, "--sarif", projectPath) // #nosec G204

	cmd.Dir = projectPath
	cmd.Env = os.Environ()

	output, _ := cmd.CombinedOutput()
	log.Debugf("%s\n%s", cmd.String(), output)

	return os.Open(outputPath) // #nosec G304
}
