"""Resume a pending demo action by event ID after a workspace reviewer approves it."""
import argparse
import json
import os
import sys

from sdk import TrustMeshClient

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("event_id", type=int, help="event ID printed by demo_agent.py")
args = parser.parse_args()
token = os.getenv("TRUSTMESH_AGENT_TOKEN")
if not token:
    parser.error("set TRUSTMESH_AGENT_TOKEN to the agent's one-time-issued credential")
result = TrustMeshClient(os.getenv("TRUSTMESH_URL", "http://127.0.0.1:8000"), token).resume_tool(args.event_id)
print(json.dumps(result, indent=2))
if not result.get("executed"):
    sys.exit(1)
