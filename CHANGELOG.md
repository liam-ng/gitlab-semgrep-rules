Semgrep analyzer changelog

## v0.7.0
- Update report dependency in order to use the report schema version 14.0.0 (!17)

## v0.6.1
- Add react-dangerouslysetinnerhtml semgrep rule (!16)
- Add detect-non-literal-regexp semgrep rule (!16)
- Add detect-non-literal-fs-filename (!16)
- Add detect-object-injection (!16)

## v0.6.0
- Add eslint and react rule-sets (!12)

## v0.5.0
- Add bandit identifier to `Report.Vulnerabilities` (!10)

## v0.4.0
- Fix paths in report to be relative to project root (!6)
- Update Dockerfile to give us control over base image (!6)
- Update sarif package to support multiple runs and locations (!6)

## v0.3.0
- OWASP metadata added to bandit rule-set (!9)

## v0.2.0
- Bandit rule-set (!2)

## v0.0.1
- First pass at things (!1)
