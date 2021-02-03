ARG SCANNER_VERSION=0.39.1

FROM golang:1.15-alpine AS build

ENV CGO_ENABLED=0 GOOS=linux

WORKDIR /go/src/buildapp
COPY . .

# variable to the most recent version from the CHANGELOG.md file
RUN CHANGELOG_VERSION=$(grep -m 1 '^## v.*$' "CHANGELOG.md" | sed 's/## v//') && \
        PATH_TO_MODULE=`go list -m` && \
        go build -ldflags="-X '$PATH_TO_MODULE/metadata.AnalyzerVersion=$CHANGELOG_VERSION'" -o /analyzer

FROM returntocorp/semgrep:$SCANNER_VERSION

ARG SCANNER_VERSION
ENV SCANNER_VERSION ${SCANNER_VERSION}

COPY --from=build /analyzer /analyzer
COPY rules /rules

ENTRYPOINT []
CMD ["/analyzer", "run"]
