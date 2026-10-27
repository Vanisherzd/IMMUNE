"""Custom actions for the tool-output rails (nemo/guardrails/rails.co).

Tool results are data from the monitored system, which may itself be compromised: a log line, a config comment or a
page body can carry text addressed to the agent. Two passes, both inside NeMo Guardrails: a pattern rail that blocks
plain imperative injections outright, and a model rail (self check input, on the local model) that runs only on lines
that look addressed to an agent or name one of its tools. Ordinary log lines never reach the model.
"""
import re

from nemoguardrails.actions import action

TOOLS = (r"kill_process|cleanup_disk|clear_scratch_volume|recreate_stack|write_config|restore_config|docker_(?:start|"
         r"restart|exec)|network_repair|self_heal")
HARD = re.compile(r"(?i)(ignore (?:all |any |the )?(?:previous|prior|above|earlier) (?:instructions|rules|guidance)"
                  r"|disregard (?:your|the) (?:instructions|rules)|new instructions:|system prompt"
                  r"|(?:assistant|agent|\bai\b|operator|on-?call)[,:]? +(?:please +)?(?:run|execute|call|delete|disable|"
                  r"approve|skip|kill)"
                  r"|you (?:are|must|should|need to) (?:now )?(?:run|execute|call|approve|delete|disable|skip|kill)"
                  r"|skip (?:the |any )?(?:review|approval|check)s?|(?:approval|review)\b.{0,40}\b(?:already )?(?:granted|given|waived)"
                  r"|rm -rf /|curl [^ ]+ *\| *(?:ba)?sh)")
SUSPICIOUS = re.compile(rf"(?i)(\b(?:agent|assistant|operator|on-?call|llm|\bai\b|automation)\b|\b(?:{TOOLS})\b"
                        r"|\b(?:instruction|approve|approval|skip the review|do not (?:report|tell|check))\b)")


def _text(context):
    return (context or {}).get("user_message") or ""


@action(name="detect_embedded_instructions")
async def detect_embedded_instructions(context: dict = None):
    """True when the text is free of plain imperative injections."""
    return not HARD.search(_text(context))


@action(name="looks_addressed_to_agent")
async def looks_addressed_to_agent(context: dict = None):
    """True when the text mentions an agent, an operator or one of the agent's tools: worth a model check."""
    return bool(SUSPICIOUS.search(_text(context)))
