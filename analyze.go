package main

import (
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"gitlab.com/gitlab-org/security-products/analyzers/ruleset"
)

const (
	flagSASTExcludedPaths  = "sast-excluded-paths"
	flagSASTSemgrepMetrics = "semgrep-send-metrics"
)

// invalidExitCodes contains exit codes for which we should err
// see https://semgrep.dev/docs/cli-usage/#exit-codes
var invalidExitCodes = map[int]bool{
	1: false, // Semgrep found issues in your code
	// In the case of `2` we must inspect the SARIF output, so this is handled within the ConvertFunc
	// i.e. nosem mismatch
	2: false, // Semgrep failed
	4: true,  // Semgrep encountered an invalid pattern
	7: true,  // All rules in config are invalid
}

func analyzeFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    flagSASTSemgrepMetrics,
			Usage:   "send anonymized scan metrics to r2c",
			EnvVars: []string{"SAST_SEMGREP_METRICS"},
			Value:   true,
		},
		&cli.StringFlag{
			Name:    flagSASTExcludedPaths,
			Usage:   "See https://docs.gitlab.com/ee/user/application_security/sast/#vulnerability-filters",
			EnvVars: []string{"SAST_EXCLUDED_PATHS"},
		},
	}
}

// The nosec comments below are ignoring two false positive vulnerabilities. They are false positive as this
// program is built inside an environment (i.e. docker image) that we have full control over as well as the
// fact that we control the `projectPath` var passed into the function and accept the open file as an output.
// In other words, this function is internal to the complete program we're building and not exposed to any
// third party.
func analyze(c *cli.Context, projectPath string) (io.ReadCloser, error) {
	// Load custom config if available
	rulesetPath := filepath.Join(projectPath, ruleset.PathSAST)
	rulesetConfig, err := ruleset.Load(rulesetPath, "semgrep")
	if err != nil {
		switch err.(type) {
		case *ruleset.NotEnabledError:
			log.Debug(err)
		case *ruleset.ConfigFileNotFoundError:
			log.Debug(err)
		case *ruleset.ConfigNotFoundError:
			log.Debug(err)
		case *ruleset.InvalidConfig:
			log.Fatal(err)
		default:
			return nil, err
		}
	}

	outputPath := path.Join(projectPath, "semgrep.sarif")

	configPath, err := getConfigPath(projectPath, rulesetConfig)
	if err != nil {
		return nil, err
	}

	args := buildArgs(
		configPath,
		outputPath,
		projectPath,
		c.String(flagSASTExcludedPaths),
		c.Bool(flagSASTSemgrepMetrics),
	)

	cmd := exec.Command("semgrep", args...) // #nosec G204
	log.Debug(cmd.String())

	cmd.Dir = projectPath
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "SEMGREP_USER_AGENT_APPEND=(GitLab SAST)")

	output, err := cmd.CombinedOutput()

	if err != nil {
		log.Debugf("%s", output)

		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)

			if invalidExitCodes[waitStatus.ExitStatus()] {
				return nil, err
			}
		}
	}

	return os.Open(outputPath) // #nosec G304
}

func buildArgs(configPath, outputPath, projectPath, excludedPaths string, enableMetrics bool) []string {
	var args []string

	args = []string{
		"-f", configPath,
		"-o", outputPath,
		"--sarif",
		"--no-rewrite-rule-ids",
		"--strict",
		"--disable-version-check",
		"--no-git-ignore",
	}

	if strings.TrimSpace(excludedPaths) != "" {
		excludes := strings.Split(excludedPaths, ",")
		for _, exclude := range excludes {
			args = append(args, "--exclude", strings.TrimSpace(exclude))
		}
	}

	if enableMetrics {
		args = append(args, "--enable-metrics")
	}

	args = append(args, projectPath)

	return args
}

func getConfigPath(projectPath string, rulesetConfig *ruleset.Config) (string, error) {
	if rulesetConfig != nil && len(rulesetConfig.Passthrough) != 0 {
		return ruleset.ProcessPassthroughs(rulesetConfig, log.StandardLogger())
	}

	return path.Join("/", "rules"), nil
}
