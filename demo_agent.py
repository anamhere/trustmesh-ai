"""Exercise TrustMesh's server-side sandbox gateway with fictional data only."""
import os
from sdk import TrustMeshClient

client = TrustMeshClient(os.getenv("TRUSTMESH_URL", "http://127.0.0.1:8000"), os.environ["TRUSTMESH_AGENT_TOKEN"])
for tool, args in [
    ("search_docs", {"query": "returns"}),
    ("lookup_customer", {"customer_id": "C-100"}),
    ("send_demo_email", {"recipient": "guest@example.test", "subject": "Demo", "body": "Simulated only."}),
    ("list_demo_invoices", {"account_id": "C-100"}),
]:
    result = client.execute_tool(tool, args)
    print(tool, "=>", result.get("decision"), "state:", result.get("state"),
          "executed:", result.get("executed"), "result:", result.get("result"),
          "event:", result.get("event_id"))
    if result.get("state") == "pending_approval":
        print("Approve the event in TrustMesh, then call client.resume_tool(event_id) to execute the stored request.")
