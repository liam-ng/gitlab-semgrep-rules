#!/usr/bin/env sh

./run_semgrep_json.sh > received.json
diff -u expected.json received.json
