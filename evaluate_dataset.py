"""Compute transparent binary classification metrics on the included labeled sample."""
import csv
from pathlib import Path
from app import Agent, ActionIn, inspect_action

agent = Agent(name="Evaluator", role="evaluation", permissions='["read"]')
tp = fp = tn = fn = 0
with (Path(__file__).parent / "evaluation" / "labelled_actions.csv").open(newline="", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        result, _, _ = inspect_action(agent, ActionIn(action=row["action"], resource=row["resource"], payload=row["payload"]))
        predicted = result in ("BLOCK", "REVIEW")
        actual = row["label"] == "malicious"
        tp += actual and predicted; fp += (not actual) and predicted
        tn += (not actual) and (not predicted); fn += actual and (not predicted)
total = tp + fp + tn + fn
precision = tp / (tp + fp) if tp + fp else 0
recall = tp / (tp + fn) if tp + fn else 0
fpr = fp / (fp + tn) if fp + tn else 0
print(f"sample_count={total} tp={tp} fp={fp} tn={tn} fn={fn}")
print(f"precision={precision:.3f} recall={recall:.3f} false_positive_rate={fpr:.3f}")
print("Warning: this tiny hand-labeled demonstration set is not representative and is not a real-world accuracy claim.")
