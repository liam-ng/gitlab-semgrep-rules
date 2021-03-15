#!/usr/bin/env sh

semgrep -f ../rules --json . --strict --no-rewrite-rule-ids | python -mjson.tool
