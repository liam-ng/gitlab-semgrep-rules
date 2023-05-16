# Semgrep analyzer

This analyzer is a wrapper around [Semgrep](https://github.com/returntocorp/semgrep).
It's written in Go using
the [common library](https://gitlab.com/gitlab-org/security-products/analyzers/common)
shared by all analyzers.

The [common library](https://gitlab.com/gitlab-org/security-products/analyzers/common)
contains documentation on how to run, test and modify this analyzer.

## Rules

You can find details about the rulesets and their sources in
[`RULES.md`](RULES.md).

### Image integration tests

Image integration tests are executed on CI to check the Docker image of the analyzer using [RSpec](https://rspec.info/).
They check the output and exit code of the analyzer, as well as the SAST report it generates.
The image integration tests can also be executed locally, for example, to check an image that was built locally using `docker build`<sup>[3](#unable-to-build-image)</sup>.

#### Running image integration tests using the integration-test Docker image

See the [instructions](https://gitlab.com/gitlab-org/security-products/analyzers/integration-test/-/blob/main/README.md#how-to-run-the-integration-test-docker-container-locally) from the `integration-test` project.

#### Updating the integration test expected JSON

Making changes to rules or the semgrep codebase often results in changes to the expected JSON. Rather than manually updating these files,
the expect JSON, found in `qa/expect`, can be updated using the script [analyzer-refresh-expected-json](https://gitlab.com/gitlab-org/secure/tools/analyzer-scripts/-/blob/master/analyzer-refresh-expected-json). To run the script, follow the instructions in the [analyzer-scripts README](https://gitlab.com/gitlab-org/secure/tools/analyzer-scripts) and then run `analyzer-refresh-expected-json` from your `semgrep` development directory.

This script runs the integration tests from the [integration-test Docker image](#running-image-integration-tests-using-the-integration-test-docker-image) and adds an additional environment variable. This variable causes the integration specs to overwrite the `qa/expect` JSON files with the JSON generated during the specs.

Once that's complete, the `analyzer-refresh-expected-json` then sanitizes the JSON by replacing `scan.start_time`, `scan.end_time`, `vulnerabilities.id` and `scan.analyzer.version` to `:SKIP:`.

## Contributing

Contributions are welcome, see [`CONTRIBUTING.md`](CONTRIBUTING.md) for more details.

## Troubleshooting

### Unable to build image

If you encounter the error message `Unknown machine architecture: aarch64` while attempting to build an analyzer Docker image locally, this is due to the fact that we currently only support building on an `amd64` architecture, such as an Intel Mac. Other architectures, such as the `ARM` Apple Silicon M1 chip, are not currently supported.

## License

This code is distributed under the MIT Expat license, see the [LICENSE](LICENSE) file.
