#!/usr/bin/env sh

semgrep -f ../rules --json . --strict --no-rewrite-rule-ids | python sort_n_print_json.py
