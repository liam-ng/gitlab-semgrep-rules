# Semgrep analyzer

This analyzer is a wrapper around [Semgrep](https://github.com/returntocorp/semgrep).
It's written in Go using
the [common library](https://gitlab.com/gitlab-org/security-products/analyzers/common)
shared by all analyzers.

The [common library](https://gitlab.com/gitlab-org/security-products/analyzers/common)
contains documentation on how to run, test and modify this analyzer.

## Rules

When the Semgrep analyzer is executed, it's provided with a directory of rule
files (the "ruleset"). You can find the default rulset under the `/rules`
directory, and a collection of archived rules under `/rules_archived`.

Archived rules can be re-enabled using [custom
rulesets](https://docs.gitlab.com/ee/user/application_security/sast/#customize-rulesets).

You can find more details about rulesets and their sources in
[`RULES.md`](RULES.md).

## Contributing

Contributions are welcome, see [`CONTRIBUTING.md`](CONTRIBUTING.md) for more details.

## License

This code is distributed under the MIT Expat license, see the [LICENSE](LICENSE) file.
