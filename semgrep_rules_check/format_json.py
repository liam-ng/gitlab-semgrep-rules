import json
import sys

data = json.load(sys.stdin)

def semgrep_sort_key(result):
    return "{}:{}:{}".format(result["path"], result["start"]["line"], result["check_id"])

data["results"] = sorted(data["results"], key=semgrep_sort_key)

for r in data["results"]:
    del r["extra"]["fingerprint"] # unsed property and not unique across vulns
    del r["extra"]["metavars"]
    del r["extra"]["engine_kind"]

del data["paths"]

# remove semgrep version property from diff match
if data.get("version", None) is not None:
    del data["version"]

print(json.dumps(data, indent=4))
