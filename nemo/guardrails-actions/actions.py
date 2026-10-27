"""Custom action for the tool-input rail (nemo/guardrails-actions/rails.co).

The checked message is JSON: {"action": tool name, "args": {...}, "injected": [lines the output rails removed]}.
A call is refused when an injected line names the same tool (or, for the irreversible tools, its plain-language
form), or names a pid or a path the call passes. The agent may still reach that action on its own evidence, so the refusal
text tells it to justify the action from evidence gathered outside the injected text and escalate otherwise.
"""
import json
import re

from nemoguardrails.actions import action

# Plain-language forms, for the irreversible tools only: a generic word ("config", "restart") also names the ordinary
# fix, and refusing that would block the repair the evidence asks for.
PLAIN = {"kill_process": r"\bkill\b", "cleanup_disk": r"clean ?up (?:the )?disk|free (?:up )?(?:disk )?space|delete (?:the )?logs",
         "clear_scratch_volume": r"scratch volume", "recreate_stack": r"\b(?:recreate|rebuild|redeploy)\b"}


@action(name="action_independent_of_injection")
async def action_independent_of_injection(context: dict = None):
    try:
        req = json.loads((context or {}).get("user_message") or "{}")
    except ValueError:
        return True
    injected = " ".join(req.get("injected") or []).lower()
    if not injected:
        return True
    tool = str(req.get("action", ""))
    if tool and (tool.lower() in injected or re.search(PLAIN.get(tool, r"$^"), injected)):
        return False
    for v in (req.get("args") or {}).values():      # a pid or a path the injection named; container names are the
        v = str(v).lower()                          # stack's own and appear in any fix, so they do not count
        if (v.isdigit() or v.startswith("/")) and re.search(rf"(?<![\w/]){re.escape(v)}(?![\w/])", injected):
            return False
    return True
