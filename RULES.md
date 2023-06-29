# Rules

## Adding, modifying, and deleting rules

The [`sast-rules`](https://gitlab.com/gitlab-org/security-products/sast-rules)
repository is the source of truth for the GitLab Semgrep rulesets. Changes to rules
should be made in `sast-rules`. A CI job is responsible for validating and publishing
the latest rules, which will eventually be consumed by the Semgrep analyzer here.
