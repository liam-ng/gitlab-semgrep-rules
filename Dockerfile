# When updating version make sure to check on semgrepignore file as well
ARG SCANNER_VERSION=1.23.0
ARG POST_ANALYZER_SCRIPTS_VERSION=0.2.0
ARG TRACKING_CALCULATOR_VERSION=2.3.3
ARG VET_VERSION=0.18.3
ARG STENCILS_VERSION=0.2.0

FROM registry.gitlab.com/security-products/post-analyzers/scripts:${POST_ANALYZER_SCRIPTS_VERSION} AS scripts
FROM registry.gitlab.com/security-products/post-analyzers/tracking-calculator:${TRACKING_CALCULATOR_VERSION} AS tracking
FROM registry.gitlab.com/security-products/vet:${VET_VERSION} AS vet
FROM registry.gitlab.com/gitlab-org/security-products/vet/stencils:${STENCILS_VERSION} AS recipes

FROM golang:1.18-alpine AS build

ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /go/src/buildapp
COPY . .

# variable to the most recent version from the CHANGELOG.md file
RUN CHANGELOG_VERSION=$(grep -m 1 '^## v.*$' "CHANGELOG.md" | sed 's/## v//') && \
        PATH_TO_MODULE=`go list -m` && \
        go build -ldflags="-X '$PATH_TO_MODULE/metadata.AnalyzerVersion=$CHANGELOG_VERSION'" -o /analyzer-semgrep

FROM python:3.9-alpine

ARG SCANNER_VERSION
ENV SCANNER_VERSION ${SCANNER_VERSION}
ENV SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE "/semgrepignore"
ENV PIP_NO_CACHE_DIR=off
ENV VET_CONFIGURATION_FILE="/verify/semgrep.toml"
ENV SAST_RULES_VERSION=1.3.29

# Run VET FP reduction only on Go files
ENV VET_LANG_EXT=".go"

RUN mkdir -p /etc/ssl/certs/ && \
    touch /etc/ssl/certs/ca-certificates.crt && \
    chmod g+w /etc/ssl/certs/ca-certificates.crt

COPY --from=build /analyzer-semgrep /analyzer-binary
COPY semgrepignore /semgrepignore
RUN mkdir /.cache && \
    chmod -R g+rw /.cache && \
    \
    # Configure CA Certificates
    mkdir -p /etc/ssl/certs/ && \
    touch /etc/ssl/certs/ca-certificates.crt && \
    chmod g+w /etc/ssl/certs/ca-certificates.crt && \
    \
    # Install semgrep and additional tools
    apk add --no-cache git && \
    apk add --no-cache --virtual=.build-only-deps gcc musl-dev && \
    pip install semgrep==$SCANNER_VERSION && \
    apk del .build-only-deps

RUN git clone \
    --depth 1 \
    --branch "v${SAST_RULES_VERSION}" \
    --no-checkout \
    https://gitlab.com/gitlab-org/security-products/sast-rules.git \
    /sast-rules

RUN mkdir -p rules

RUN cd sast-rules && \
    # pull only `dist` folder when checking out
    git sparse-checkout set dist && \
    git checkout "v${SAST_RULES_VERSION}" && \
    cp dist/eslint.yml /rules && \
    cp dist/find_sec_bugs_scala.yml /rules && \
    cp dist/flawfinder.yml /rules && \
    cp dist/find_sec_bugs.yml /rules && \
    cp dist/security_code_scan.yml /rules && \
    cp dist/gosec.yml /rules && \
    cp dist/bandit.yml /rules

COPY --from=tracking /analyzer-tracking /analyzer-tracking
COPY --from=scripts /start.sh /analyzer
COPY --from=vet /usr/bin/analyzer /vet
COPY --from=recipes /config/verify /verify

# Allow running on m1s in Docker
RUN sed -i 's/if platform.machine() in {"arm64", "aarch64"} and platform.system() == "Linux":/if 0:/g' /usr/local/lib/python3.9/site-packages/semgrep/cli.py

ENTRYPOINT []
CMD ["/analyzer", "run"]
