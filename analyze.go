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
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v2"

	"gitlab.com/gitlab-org/security-products/analyzers/ruleset"
	"gitlab.com/gitlab-org/security-products/analyzers/semgrep/cliarg"
)

const (
	flagSASTExcludedPaths          = "sast-excluded-paths"
	flagSASTSemgrepMetrics         = "semgrep-send-metrics"
	flagSASTExperimentalFeatures   = "sast-experimental-features"
	flagSASTAllowedCLIOpts         = "sast-scanner-allowed-cli-opts"
	flagSASTSegrepRuleConfigDir    = "semgrep-rule-config-dir"
	flagSASTSegrepRuleConfigDirEnv = "SAST_SEMGREP_RULE_CONFIG_DIR"
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

// highFPRules is a map of analyzer names to rule IDs of rules that are known to
// cause a high FP rate.
var highFPRules = map[string][]string{
	"eslint.yml": {"eslint.security/detect-object-injection-1"},
}

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
		&cli.StringFlag{
			Name:    flagSASTSegrepRuleConfigDir,
			Usage:   "Configuration Directory",
			EnvVars: []string{flagSASTSegrepRuleConfigDirEnv},
			Value:   "/rules",
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

	configPath, err := getConfigPath(c, projectPath, rulesetConfig)
	if err != nil {
		return nil, err
	}

	if err = os.Setenv(flagSASTSegrepRuleConfigDirEnv, configPath); err != nil {
		return nil, err
	}

	if c.Bool(flagSASTExperimentalFeatures) {
		for rulefileName, ruleIDs := range highFPRules {
			rulefilePath := path.Join(configPath, rulefileName)
			if err = removeRulesFromFile(rulefilePath, ruleIDs); err != nil {
				log.Debugf("SAST_EXPERIMENTAL_FEATURES was enabled but the analyzer failed to remove high-FP rules: %s", err)
			}
		}
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

	if enableMetrics {
		args = append(args, "--enable-metrics")
	}

	if opts := parseAllowedCLIOpts(scannerOpts); len(opts) > 0 {
		args = append(args, opts...)
	}

	return args
}

func getConfigPath(c *cli.Context, projectPath string, rulesetConfig *ruleset.Config) (string, error) {
	if rulesetConfig != nil && len(rulesetConfig.Passthrough) != 0 {
		return ruleset.ProcessPassthroughs(rulesetConfig, log.StandardLogger())
	}

	return c.String(flagSASTSegrepRuleConfigDir), nil
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
	// We only care about the ID in this context.
	ID   string                 `yaml:"id"`
	Rest map[string]interface{} `yaml:",inline"`
}

// removeRulesFromFile removes any Semgrep rules from the file whose `id` contains
// any value in ruleIDs as a substring. For example:
//
// rule ID in file   			ruleIDs     	remove?
// ---------------   			-------     	-------
// bandit.108-1      			bandit.108  	yes
// bandit.B313.B314.B315      	bandit.B314  	no
func removeRulesFromFile(file string, ruleIDs []string) error {
	var ruleFile semgrepRuleFile

	fileContent, err := ioutil.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read rule file at %s: %w", file, err)
	}

	if err = yaml.Unmarshal(fileContent, &ruleFile); err != nil {
		return fmt.Errorf("parse rule file at %s: %w", file, err)
	}

	shouldReserialise := false
	for idx, rule := range ruleFile.Rules {
		if contains(rule.ID, ruleIDs) {
			shouldReserialise = true
			ruleFile.Rules = remove(ruleFile.Rules, idx)
		}
	}

	if shouldReserialise {
		out, err := yaml.Marshal(ruleFile)
		if err != nil {
			return fmt.Errorf("marshal modified rule file %w", err)
		}

		if err = ioutil.WriteFile(file, out, 0666); err != nil {
			return fmt.Errorf("write modified rule file to %s: %w", file, err)
		}
	}

	return nil
}

// contains returns whether ruleID is present in ruleIDs.
func contains(ruleID string, ruleIDs []string) bool {
	for _, rid := range ruleIDs {
		// Some rule IDs we process here get suffixed by the `ruleset` package.
		// e.g. bandit.B108 is represented as bandit.B108-1 and bandit.B108-2
		if strings.Contains(rid, ruleID) {
			return true
		}
	}

	return false
}

// remove deletes the element at i from s by replacing s[i] with the last element
// of the slice before trimming it from the slice. Since the order of rules isn't
// important, this provides better performance compared to shifting elements for
// a delete-in-place operation.
func remove(s []semgrepRule, i int) []semgrepRule {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
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
