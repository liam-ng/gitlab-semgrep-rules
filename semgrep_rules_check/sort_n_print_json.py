import json
import sys

data = json.load(sys.stdin)

def semgrep_sort_key(result):
    return "{}:{}:{}".format(result["path"], result["start"]["line"], result["check_id"])

data["results"] = sorted(data["results"], key=semgrep_sort_key)

print(json.dumps(data, indent=4))
