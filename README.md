# Semgrep analyzer

The Semgrep analyzer performs SAST scanning on repositories containing code written in several languages:

* C# (.NET)
* C
* Go
* Java
* JavaScript
* Python
* Scala
* TypeScript

The analyzer wraps [Semgrep](https://github.com/returntocorp/semgrep), and is written in Go. It's structured similarly to other Static Analysis analyzers because it uses the shared [command](https://gitlab.com/gitlab-org/security-products/analyzers/command) package.

The analyzer is built and published as a Docker image in the GitLab Container Registry associated with this repository. You would typically use this analyzer in the context of a [SAST](https://docs.gitlab.com/ee/user/application_security/sast) job in your CI/CD pipeline. However, if you're contributing to the analyzer or you need to debug a problem, you can run, debug, and test locally using Docker.

For instructions on local development, please refer to the [README in Analyzer Scripts](https://gitlab.com/gitlab-org/secure/tools/analyzer-scripts/-/blob/master/analyzers-common-readme.md).

## SAST Rules

The [`sast-rules`](https://gitlab.com/gitlab-org/security-products/sast-rules) repository is the source of truth for the GitLab Semgrep rulesets. Changes to rules should be made in `sast-rules`. A CI job is responsible for validating and publishing the latest rules, which will eventually be consumed by the Semgrep analyzer here.

## Versioning and release process

Please check the [versioning and release process documentation](https://gitlab.com/gitlab-org/security-products/analyzers/common#versioning-and-release-process).

## Contributing

Contributions are welcome, see [`CONTRIBUTING.md`](CONTRIBUTING.md) for more details.

## License

This code is distributed under the MIT Expat license, see the [LICENSE](LICENSE) file.
