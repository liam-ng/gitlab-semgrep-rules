package main

import (
	"io/ioutil"
	"os"
	"path"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildArgs(t *testing.T) {
	tests := []struct {
		name          string
		excludedPaths string
		enableMetrics bool
		passedCLIOpts string
		want          []string
	}{
		{
			name:          "Empty Exclude",
			excludedPaths: "",
			enableMetrics: false,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
			},
		},
		{
			name:          "Empty Exclude with whitespace",
			excludedPaths: "  ",
			enableMetrics: false,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
			},
		},
		{
			name:          "Default Exclude",
			excludedPaths: "spec,test,tests,tmp",
			enableMetrics: false,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--exclude", "spec",
				"--exclude", "test",
				"--exclude", "tests",
				"--exclude", "tmp",
			},
		},
		{
			name:          "Glob Exclude",
			excludedPaths: "test/*.js,*.rb",
			enableMetrics: false,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--exclude", "test/*.js",
				"--exclude", "*.rb",
			},
		},
		{
			name:          "Exclude with whitespace",
			excludedPaths: "spec, test, tests, tmp",
			enableMetrics: false,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--exclude", "spec",
				"--exclude", "test",
				"--exclude", "tests",
				"--exclude", "tmp",
			},
		},
		{
			name:          "Enabled Metrics",
			excludedPaths: "",
			enableMetrics: true,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--enable-metrics",
			},
		},
		{
			name:          "CLI Opts: append value to flag name with = separator",
			excludedPaths: "",
			passedCLIOpts: "--max-memory=1024",
			enableMetrics: true,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--enable-metrics",
				"--max-memory", "1024",
			},
		},
		{
			name:          "CLI Opts: Include both allowed and not-allowed flag with = separator",
			excludedPaths: "",
			passedCLIOpts: "--max-memory=1024 --optimizations=all", // invalid
			enableMetrics: true,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--enable-metrics",
				"--max-memory", "1024",
			},
		},
		{
			name:          "CLI Opts: Include only allowed flag with space separator",
			excludedPaths: "",
			passedCLIOpts: "--max-memory 1024",
			enableMetrics: true,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--enable-metrics",
				"--max-memory", "1024",
			},
		},
		{
			name:          "CLI Opts: Include both allowed and not-allowed flag with space separator",
			excludedPaths: "",
			passedCLIOpts: "--max-memory 1024 --optimizations all",
			enableMetrics: true,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--enable-metrics",
				"--max-memory", "1024",
			},
		},
		{
			name:          "CLI Opts: Include only not-allowed flag",
			excludedPaths: "",
			passedCLIOpts: "--optimizations=all",
			enableMetrics: true,
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--enable-metrics",
			},
		},
	}

	for _, tt := range tests {
		tt := tt // NOTE: https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildArgs("configPath", "outputPath", "projectPath", tt.excludedPaths, tt.passedCLIOpts, tt.enableMetrics)

			if !reflect.DeepEqual(tt.want, got) {
				t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", tt.want, got)
			}
		})
	}
}

func TestRemoveRulesFromFile(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)

	rulefileName := "remove_rules_from_file.yml"
	rulefileOriginal := path.Join(wd, "testdata", rulefileName)
	rulefileTesting := path.Join(t.TempDir(), rulefileName)

	// copy original rulefile to a temporary one for testing
	rulefileTestingContent, err := ioutil.ReadFile(rulefileOriginal)
	require.NoError(t, err)
	require.NoError(t, ioutil.WriteFile(rulefileTesting, rulefileTestingContent, 0666))

	// remove some rules
	ruleToRemove := "eslint.detect-object-injection"
	require.NoError(t, removeRulesFromFile(rulefileTesting, []string{ruleToRemove}))

	// assert
	modifiedRulefileContents, err := ioutil.ReadFile(rulefileTesting)
	assert.NotContains(t, string(modifiedRulefileContents), ruleToRemove)
	assert.Contains(t, string(modifiedRulefileContents), "eslint.detect-non-literal-fs-filename", "should not remove unmatched rules")
	assert.Equal(t, 4280, len(modifiedRulefileContents), "should not result in an empty file")
}
