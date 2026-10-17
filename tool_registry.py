"""Fixed, side-effect-bounded demonstration tools run inside the gateway process."""
from __future__ import annotations
from typing import Any

DOCS = {"returns": "Fictional demo policy: returns accepted within 30 days."}
CUSTOMERS = {
    "C-100": {"id": "C-100", "name": "Avery Example", "plan": "starter"},
    "C-200": {"id": "C-200", "name": "Jordan Sample", "plan": "enterprise"},
}
INVOICES = {"C-100": [{"invoice": "INV-DEMO-01", "amount": 25.0, "currency": "USD"}],
            "C-200": [{"invoice": "INV-DEMO-02", "amount": 75.0, "currency": "USD"}]}
OUTBOX: list[dict[str, str]] = []


def describe(name: str, args: dict[str, Any]) -> tuple[str, str, str]:
    """Derive policy inputs on the server. Clients cannot choose a weaker action label."""
    if name == "search_docs":
        query = _required(args, "query", 300)
        return "read", "knowledge_base", query
    if name == "lookup_customer":
        customer_id = _required(args, "customer_id", 20)
        return "read", "customer_record", customer_id
    if name == "send_demo_email":
        recipient = _required(args, "recipient", 254)
        subject = _required(args, "subject", 200)
        body = _required(args, "body", 2000)
        return "send", "email", f"to:{recipient} subject:{subject} body:{body}"
    if name == "list_demo_invoices":
        account_id = _required(args, "account_id", 20)
        return "export", "billing", account_id
    raise ValueError("Tool is not in the fixed safe sandbox registry")


def execute(name: str, args: dict[str, Any]) -> dict[str, Any]:
    """Execute only fixed local fixtures; no shell, SQL, arbitrary code, or network calls."""
    if name == "search_docs":
        query = _required(args, "query", 300).lower()
        return {"matches": [value for key, value in DOCS.items() if key in query or query in value.lower()]}
    if name == "lookup_customer":
        return CUSTOMERS.get(_required(args, "customer_id", 20), {"error": "No fictional demo customer found"})
    if name == "send_demo_email":
        recipient = _required(args, "recipient", 254)
        if not recipient.endswith("@example.test"):
            return {"sent": False, "error": "Sandbox accepts only reserved example.test addresses"}
        OUTBOX.append({"to": recipient, "subject": _required(args, "subject", 200),
                       "body": _required(args, "body", 2000), "mode": "simulated"})
        return {"sent": True, "mode": "simulated", "outbox_count": len(OUTBOX)}
    if name == "list_demo_invoices":
        account_id = _required(args, "account_id", 20)
        if account_id not in INVOICES: return {"error": "No fictional demo account found"}
        return {"account": account_id, "invoices": INVOICES[account_id]}
    raise ValueError("Tool is not in the fixed safe sandbox registry")


def _required(args: dict[str, Any], key: str, limit: int) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{key} must be a non-empty string of at most {limit} characters")
    return value.strip()
