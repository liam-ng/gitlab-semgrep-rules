#!/usr/bin/env sh

./run_semgrep_json.sh > received.json

negatives=$(grep -n negatives received.json)
if [ "$negatives" != "" ]; then
  printf "$negatives\n"
  exit 1
fi

diff -u expected.json received.json
