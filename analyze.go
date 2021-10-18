package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"gitlab.com/gitlab-org/security-products/analyzers/ruleset"
)

const (
	flagSASTExcludedPaths  = "sast-excluded-paths"
	flagSASTSemgrepMetrics = "semgrep-send-metrics"
)

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
		return nil, err
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

	if excludedPaths != "" {
		excludes := strings.Split(excludedPaths, ",")
		for _, exclude := range excludes {
			args = append(args, "--exclude", exclude)
		}
	}

	if enableMetrics {
		args = append(args, "--enable-metrics")
	}

	args = append(args, projectPath)

	return args
}

func getConfigPath(projectPath string, rulesetConfig *ruleset.Config) (string, error) {
	if rulesetConfig != nil && len(rulesetConfig.PassThrough) != 0 {
		passThrough := rulesetConfig.PassThrough[0]
		configPath, err := processPassthrough(projectPath, passThrough)

		if err != nil {
			return "", err
		}

		return configPath, nil
	}

	return path.Join("/", "rules"), nil
}

// processPassthrough processes the ruleset and returns the set of args to appended
// to the analyzer command
func processPassthrough(projectPath string, passThrough ruleset.PassThrough) (string, error) {
	value := passThrough.Value
	if passThrough.Type == ruleset.PassThroughFile {
		return passthroughFile(projectPath, value)
	} else if passThrough.Type == ruleset.PassThroughRaw {
		return passthroughRaw(value)
	} else {
		return "", fmt.Errorf("unsupported passthrough type: %s", passThrough.Type)
	}
}

// passthroughFile will check to make sure file/dir exists
func passthroughFile(projectPath string, filename string) (string, error) {
	configPath := filepath.Join(projectPath, cleanPath(filename))
	if _, err := os.Stat(configPath); err != nil {
		return "", err
	}

	log.Infof("Using config from custom ruleset passthrough file: %s\n", filename)
	return configPath, nil
}

// passthroughRaw writes raw configuration to a file
func passthroughRaw(raw string) (string, error) {
	// create tmp config for raw values from the passthrough to be loaded into
	tmpConfig, err := ioutil.TempFile("", "rules*.yml")
	if err != nil {
		return "", fmt.Errorf("failed to create tmp semgrep rules file")
	}

	if _, err = tmpConfig.Write([]byte(raw)); err != nil {
		return "", fmt.Errorf("failed to write to create tmp semgrep rules file")
	}
	log.Info("Loading config from custom ruleset via raw passthrough")

	return tmpConfig.Name(), nil
}

// CleanPath makes a path safe for use with filepath.Join. This is done by not
// only cleaning the path, but also (if the path is relative) adding a leading
// '/' and cleaning it (then removing the leading '/'). This ensures that a
// path resulting from prepending another path will always resolve to lexically
// be a subdirectory of the prefixed path. This is all done lexically, so paths
// that include symlinks won't be safe as a result of using CleanPath.
//
// This function comes from runC (libcontainer/utils/utils.go):
// https://github.com/opencontainers/runc/blob/d636ad6256f9194b0f4c6ee181e75fb36e3446d8/libcontainer/utils/utils.go#L53
func cleanPath(path string) string {
	// Deal with empty strings nicely.
	if path == "" {
		return ""
	}

	// Ensure that all paths are cleaned (especially problematic ones like
	// "/../../../../../" which can cause lots of issues).
	path = filepath.Clean(path)

	// If the path isn't absolute, we need to do more processing to fix paths
	// such as "../../../../<etc>/some/path". We also shouldn't convert absolute
	// paths to relative ones.
	if !filepath.IsAbs(path) {
		path = filepath.Clean(string(os.PathSeparator) + path)
		// This can't fail, as (by definition) all paths are relative to root.
		path, _ = filepath.Rel(string(os.PathSeparator), path)
	}

	// Clean the path again for good measure.
	return filepath.Clean(path)
}
