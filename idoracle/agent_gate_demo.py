"""Show the agent action effect gate: does a tool call REALLY commit, or just say it did?

    python idoracle/agent_gate_demo.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import agent_gate  # noqa: E402

TS = "2026-06-22T00:00:00+00:00"
SECRET = "agent-demo"

store = []


def commit_tool(payload):       # really commits the record
    store.append(payload)
    return {"ok": True, "id": 1}


def noop_tool(payload):         # claims success, commits NOTHING (the silent no-op)
    return {"ok": True, "id": 2}


def observe(token):             # a separate committed-state read
    return any(token in str(t) for t in store)


def main():
    print("Agent action effect gate: does the tool call REALLY commit, or just say it did?\n")
    print(f"{'tool behaviour':<34}{'tool says':<12}{'committed':<12}{'gate verdict'}")
    print("-" * 72)
    for label, tool in [("really commits the record", commit_tool),
                        ("returns ok, commits NOTHING", noop_tool)]:
        store.clear()
        rec, _, f = agent_gate.gate_effect(
            lambda tok: tool({"title": "ticket", "canary": tok}), observe,
            created_at=TS, secret=SECRET, action="create_ticket")
        print(f"{label:<34}{'ok':<12}{str(f['observed']):<12}{rec.overall}  ({f['verdict']})")

    store.clear()
    rec, _, f = agent_gate.gate_effect(
        lambda tok: commit_tool({"canary": tok}), observe, qualified=False,
        created_at=TS, secret=SECRET, action="send_email_no_inbox")
    print(f"{'no committed-state view to read':<34}{'ok':<12}{'n/a':<12}"
          f"{rec.overall}  ({f['verdict']})")

    store.clear()
    rec, artifact, _ = agent_gate.gate_effect(
        lambda tok: commit_tool({"canary": tok}), observe, created_at=TS, secret=SECRET,
        action="create_ticket")
    v = agent_gate.verify_effect(rec, artifact, SECRET)
    print(f"\nA2A handoff: a downstream agent re-derives the verdict LLM-free before "
          f"consuming the result -> ok={v['ok']} (consistent={v['verdict_consistent']})")


if __name__ == "__main__":
    main()
