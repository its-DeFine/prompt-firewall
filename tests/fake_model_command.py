import json
import sys


payload = json.loads(sys.stdin.read())
source_ids = [source["id"] for source in payload.get("sources", [])]
print(
    json.dumps(
        {
            "action_type": "summarize",
            "source_ids": source_ids,
            "answer": "Command model treated external content as data.",
        }
    )
)
