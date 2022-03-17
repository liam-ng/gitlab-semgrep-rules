import json
import sys

data = json.load(sys.stdin)

def semgrep_sort_key(result):
    return "{}:{}:{}".format(result["path"], result["start"]["line"], result["check_id"])

data["results"] = sorted(data["results"], key=semgrep_sort_key)

for r in data["results"]:
    del r["extra"]["metavars"]

del data["paths"]

print(json.dumps(data, indent=4))
