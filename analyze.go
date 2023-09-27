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

	ruleset "gitlab.com/gitlab-org/security-products/analyzers/ruleset/v2"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/cliarg"
)

const (
	flagSASTExcludedPaths        = "sast-excluded-paths"
	flagSASTSemgrepMetrics       = "semgrep-send-metrics"
	flagSASTExperimentalFeatures = "sast-experimental-features"
	flagSASTAllowedCLIOpts       = "sast-scanner-allowed-cli-opts"
)

var (
	// allowedCliOpts is the set of CLI options that are allowed to pass to
	// the underlying security scanner. see https://gitlab.com/gitlab-org/gitlab/-/issues/368565
	allowedCliOpts = []string{"--max-memory"}
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

var defaultConfigPath = path.Join("/", "rules")

func analyzeFlags() []cli.Flag {
	return []cli.Flag{
		&cli.BoolFlag{
			Name:    flagSASTSemgrepMetrics,
			Usage:   "send anonymized scan metrics to r2c",
			EnvVars: []string{"SAST_SEMGREP_METRICS"},
			Value:   true,
		},
		&cli.BoolFlag{
			Name:    flagSASTExperimentalFeatures,
			Usage:   "See https://docs.gitlab.com/ee/user/application_security/sast/index.html#experimental-features",
			EnvVars: []string{"SAST_EXPERIMENTAL_FEATURES"},
		},
		&cli.StringFlag{
			Name:    flagSASTExcludedPaths,
			Usage:   "See https://docs.gitlab.com/ee/user/application_security/sast/#vulnerability-filters",
			EnvVars: []string{"SAST_EXCLUDED_PATHS"},
		},
		&cli.StringFlag{
			Name:    flagSASTAllowedCLIOpts,
			Usage:   "See https://docs.gitlab.com/ee/user/application_security/sast/#security-scanner-configuration",
			EnvVars: []string{"SAST_SCANNER_ALLOWED_CLI_OPTS"},
		},
	}
}

// The nosec comments below are ignoring two false positive vulnerabilities. They are false positive as this
// program is built inside an environment (i.e. docker image) that we have full control over as well as the
// fact that we control the `projectPath` var passed into the function and accept the open file as an output.
// In other words, this function is internal to the complete program we're building and not exposed to any
// third party.
func analyze(c *cli.Context, projectPath string) (io.ReadCloser, error) {
	rulesetPath := filepath.Join(projectPath, ruleset.PathSAST)

	rulesetConfig, err := ruleset.Load(rulesetPath, "semgrep", log.StandardLogger())
	if err != nil {
		return nil, err
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
		c.String(flagSASTAllowedCLIOpts),
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

func buildArgs(configPath, outputPath, projectPath, excludedPaths, scannerOpts string, enableMetrics bool) []string {
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

	args = append(args, "--metrics")
	if enableMetrics {
		args = append(args, "on")
	} else {
		args = append(args, "off")
	}

	if opts := parseAllowedCLIOpts(scannerOpts); len(opts) > 0 {
		args = append(args, opts...)
	}

	if level, ok := os.LookupEnv("SECURE_LOG_LEVEL"); ok && strings.ToLower(level) == "debug" {
		args = append(args, "--verbose")
	}

	return args
}

func getConfigPath(projectPath string, rulesetConfig *ruleset.Config) (string, error) {
	if rulesetConfig != nil && len(rulesetConfig.Passthrough) != 0 {
		return ruleset.ProcessPassthroughs(rulesetConfig, log.StandardLogger())
	}

	return defaultConfigPath, nil
}

// semgrepRuleFile represents the structure of a Semgrep rule YAML file.
type semgrepRuleFile struct {
	Rules []semgrepRule `yaml:"rules"`
}

// semgrepRule is an abridged representation of a single Semgrep file within
// a YAML file. The `,inline` flag is used to collect the properties of the rule
// we're not interested in. See https://pkg.go.dev/gopkg.in/yaml.v3#Marshal
// for more information.
type semgrepRule struct {
	ID       string `yaml:"id"`
	Metadata struct {
		PrimaryIdentifier    string `yaml:"primary_identifier"`
		SecondaryIdentifiers []struct {
			Name  string `yaml:"name"`
			Type  string `yaml:"type"`
			Value string `yaml:"value"`
		} `yaml:"secondary_identifiers"`
	} `yaml:"metadata"`
	Rest map[string]interface{} `yaml:",inline"`
}

// parseAllowedCLIOpts parses arg str passed to SAST_SCANNER_ALLOWED_CLI_OPTS CI var and returns only
// those args/flags that are present in `allowedCliOpts`. Below are some example input representations:
//
// "--arg1 --arg2 -arg3"       // regular flags with different prefixes(-/--)
// "--arg1 val --arg2 val"     // regular arg name with value separated by space
// "-arg1 val -arg2 val"       // aliased arg name with value separated by space
// "--arg1 val --arg2"         // combination of regular arg with space separated value and a flag
// "--arg1=val --arg2=val"     // regular arg name with value separated by equals(=)
// "--arg1=val -arg2=val"      // regular args with different prefix - and --
// "--arg1=val --arg2"         // combination of regular arg with equals(=) separated value and a flag
func parseAllowedCLIOpts(scannerOpts string) (args []string) {
	if cliArgStr := strings.TrimSpace(scannerOpts); cliArgStr != "" {
		cliArgs, invalid := cliarg.Parse(cliArgStr)
		if len(invalid) > 0 {
			log.Warnf("skipping following values as they are not represented under any flag: %s", invalid)
		}
		for _, arg := range cliArgs {
			if !isFlagAllowed(arg) {
				log.Warnf("skipping '%s' arg as it does not fall under allowed list of CLI args: %s", arg.Name, allowedCliOpts)
				continue
			}
			if arg.IsFlag {
				args = append(args, arg.Name)
			} else {
				args = append(args, arg.Name, arg.Value)
			}
		}
	}
	return
}

// isFlagAllowed checks if the given flag falls under the allowedCliOpts list
func isFlagAllowed(flag cliarg.Arg) bool {
	for _, opt := range allowedCliOpts {
		if flag.Name == opt {
			return true
		}
	}
	return false
}
