package main

import (
	"reflect"
	"testing"
)

func TestBuildArgs(t *testing.T) {
	tests := []struct {
		name          string
		excludedPaths string
		enableMetrics bool
		passedCLIOpts string
		envVars       map[string]string
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
		{
			name: "passes the --verbose flag when SECURE_LOG_LEVEL=debug",
			envVars: map[string]string{
				"SECURE_LOG_LEVEL": "debug",
			},
			want: []string{
				"-f", "configPath",
				"-o", "outputPath",
				"--sarif",
				"--no-rewrite-rule-ids",
				"--strict",
				"--disable-version-check",
				"--no-git-ignore",
				"--debug",
			},
		},
	}

	for _, tt := range tests {
		tt := tt // NOTE: https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		t.Run(tt.name, func(t *testing.T) {
			for key, val := range tt.envVars {
				t.Setenv(key, val)
			}

			got := buildArgs("configPath", "outputPath", "projectPath", tt.excludedPaths, tt.passedCLIOpts, tt.enableMetrics)

			if !reflect.DeepEqual(tt.want, got) {
				t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", tt.want, got)
			}
		})
	}
}
