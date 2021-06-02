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
				"--no-git-ignore",
				"projectPath",
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
				"--no-git-ignore",
				"--exclude", "spec",
				"--exclude", "test",
				"--exclude", "tests",
				"--exclude", "tmp",
				"projectPath",
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
				"--no-git-ignore",
				"--exclude", "test/*.js",
				"--exclude", "*.rb",
				"projectPath",
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
				"--no-git-ignore",
				"--enable-metrics",
				"projectPath",
			},
		},
	}

	for _, tt := range tests {
		tt := tt // NOTE: https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := buildArgs("configPath", "outputPath", "projectPath", tt.excludedPaths, tt.enableMetrics)

			if !reflect.DeepEqual(tt.want, got) {
				t.Errorf("Wrong result. Expected:\n%#v\nbut got:\n%#v", tt.want, got)
			}
		})
	}
}
