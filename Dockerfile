# When updating version make sure to check on semgrepignore file as well
ARG SCANNER_VERSION=0.115.0
ARG POST_ANALYZER_SCRIPTS_VERSION=0.0.5
ARG TRACKING_CALCULATOR_VERSION=2.2.5

FROM registry.gitlab.com/security-products/post-analyzers/scripts:${POST_ANALYZER_SCRIPTS_VERSION} AS scripts
FROM registry.gitlab.com/security-products/post-analyzers/tracking-calculator:${TRACKING_CALCULATOR_VERSION} AS tracking

FROM golang:1.17-alpine AS build
ARG SAST_RULES_VERSION=1.0.67
ARG SAST_RULES_URL=https://gitlab.com/api/v4/projects/27038823/packages/generic/rulesets


ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /go/src/buildapp
COPY . .

RUN apk add --no-cache tar curl && \
    mkdir -p /archive && \
    curl -o bandit.tar.gz ${SAST_RULES_URL}/${SAST_RULES_VERSION}/bandit.tar.gz && tar -xf bandit.tar.gz -C /archive && \
    curl -o security_code_scan.tar.gz ${SAST_RULES_URL}/${SAST_RULES_VERSION}/security_code_scan.tar.gz && tar -xf security_code_scan.tar.gz -C /archive && \
    curl -o gosec.tar.gz ${SAST_RULES_URL}/${SAST_RULES_VERSION}/gosec.tar.gz && tar -xf gosec.tar.gz -C /archive && \
    curl -o flawfinder.tar.gz ${SAST_RULES_URL}/${SAST_RULES_VERSION}/flawfinder.tar.gz && tar -xf flawfinder.tar.gz -C /archive && \
    curl -o eslint.tar.gz ${SAST_RULES_URL}/${SAST_RULES_VERSION}/eslint.tar.gz && tar -xf eslint.tar.gz -C /archive && \
    curl -o find_sec_bugs.tar.gz ${SAST_RULES_URL}/${SAST_RULES_VERSION}/find_sec_bugs.tar.gz && tar -xf find_sec_bugs.tar.gz -C /archive

# variable to the most recent version from the CHANGELOG.md file
RUN CHANGELOG_VERSION=$(grep -m 1 '^## v.*$' "CHANGELOG.md" | sed 's/## v//') && \
        PATH_TO_MODULE=`go list -m` && \
        go build -ldflags="-X '$PATH_TO_MODULE/metadata.AnalyzerVersion=$CHANGELOG_VERSION'" -o /analyzer-semgrep

FROM python:3.9-alpine

ARG SCANNER_VERSION
ENV SCANNER_VERSION ${SCANNER_VERSION}
ENV SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE "/semgrepignore"

RUN mkdir -p /etc/ssl/certs/ && \
    touch /etc/ssl/certs/ca-certificates.crt && \
    chmod g+w /etc/ssl/certs/ca-certificates.crt

COPY --from=build /analyzer-semgrep /analyzer-binary
COPY --from=build /archive/rule-sets /rules
COPY semgrepignore /semgrepignore
RUN mkdir /.cache && \
    chmod -R g+rw /.cache

RUN apk add --no-cache git && \
    pip install ruamel.yaml==0.16.12 semgrep==$SCANNER_VERSION



COPY --from=tracking /analyzer-tracking /analyzer-tracking
COPY --from=scripts /start.sh /analyzer

ENTRYPOINT []
CMD ["/analyzer", "run"]
