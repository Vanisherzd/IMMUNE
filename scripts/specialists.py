import concurrent.futures
import json
import re


SERVICE_TOOLS = ("check_health", "docker_ps", "docker_logs", "read_config", "port_check", "http_check",
                 "docker_exec", "search_runbooks")
PLATFORM_TOOLS = ("disk_usage", "service_status", "journal_tail", "port_check", "docker_exec", "docker_ps",
                  "check_health", "search_incident_knowledge")
CLOSING = "Diagnosis was parallel and read-only; any change still goes through the normal tools, the reviewer and approval."
LIMIT = 6000

PROMPTS = {
    "service": """You diagnose only the service layer of a two-container nginx stack: edge-victim is the front end and
edge-victim-app is the backend. Find the failing component and the exact log line or config line. Report short lines
starting with Hypothesis:, Evidence:, and Checks:. Never propose actions as commands; only name the checks or actions.""",
    "platform": """You diagnose only the host and resource layer: disk, inodes, memory limits, pids limits, network/DNS,
hosts file, and resolver. Report short lines starting with Hypothesis:, Evidence:, and Checks:. Never propose actions
as commands; only name the checks or actions.""",
}


def _parsed(role, text, turns, tools_called):
    hypothesis = re.search(r"^\s*(?:[-*]\s*)?Hypothesis:\s*(.+)$", text, re.I | re.M)
    evidence = re.findall(r"^\s*(?:[-*]\s*)?Evidence:\s*(.+)$", text, re.I | re.M)
    checks = re.findall(r"^\s*(?:[-*]\s*)?Checks?:\s*(.+)$", text, re.I | re.M)
    return {"role": role, "hypothesis": hypothesis.group(1).strip() if hypothesis else text.strip(),
            "evidence": [line.strip() for line in evidence], "checks": [line.strip() for line in checks],
            "turns": turns, "tools_called": tools_called}


def _model_specialist(agent, role, focus, dry_run):
    allowed = SERVICE_TOOLS if role == "service" else PLATFORM_TOOLS
    schemas = {tool["name"]: tool for tool in agent.TOOLS}
    tools = [{"type": "function", "function": schemas[name]} for name in allowed]
    client = agent.OpenAI(base_url=f"{agent.BASE}/v1", api_key="none", timeout=120)
    trace = json.dumps(agent._incident.get("trace", [])[-6:], ensure_ascii=False)[:4000]
    messages = [{"role": "system", "content": PROMPTS[role]},
                {"role": "user", "content": f"Focus: {focus or '(none supplied)'}\nRecent incident evidence: {trace}"}]
    tools_called = []
    last_text = ""
    for turn in range(1, 5):
        response = client.chat.completions.create(
            model=agent.MODEL, temperature=0, max_tokens=400, messages=messages, tools=tools, tool_choice="auto",
            extra_body={"chat_template_kwargs": {"enable_thinking": False}})
        message = response.choices[0].message
        calls = message.tool_calls or []
        last_text = (message.content or "").strip()
        if not calls:
            return _parsed(role, last_text or "No final diagnosis was returned.", turn, tools_called)
        serialized = []
        for call in calls:
            name = call.function.name
            arguments = call.function.arguments or "{}"
            serialized.append({"id": call.id, "type": "function",
                               "function": {"name": name, "arguments": arguments}})
        messages.append({"role": "assistant", "content": message.content or "", "tool_calls": serialized})
        for call in calls:
            name = call.function.name
            tools_called.append(name)
            try:
                args = json.loads(call.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            if name not in allowed or name in agent.MUTATING:
                result = "denied: specialists are read-only"
            else:
                result = agent._run_tool(name, args, dry_run)
            messages.append({"role": "tool", "tool_call_id": call.id, "content": str(result)})
    return _parsed(role, last_text or "No final diagnosis was returned.", 4, tools_called)


def _knowledge(agent, focus):
    query = focus
    if not query:
        logs = (item for item in reversed(agent._incident.get("trace", [])) if item.get("tool") == "docker_logs")
        last = next(logs, {})
        query = next((line.strip() for line in str(last.get("result", "")).splitlines()
                      if agent.SYMPTOM_RE.search(line) or agent.ACCESS_ERR_RE.search(line)), "")
    if not query:
        return {"role": "knowledge", "hypothesis": "No focus or docker log error was available for lookup.",
                "evidence": [], "checks": [], "turns": 0, "tools_called": []}
    return {"role": "knowledge", "hypothesis": agent.search_incident_knowledge(query),
            "evidence": [f"query: {query}"], "checks": [], "turns": 0, "tools_called": []}


def _section(result):
    evidence = "\n".join(f"- {line}" for line in result["evidence"]) or "- none"
    checks = "\n".join(f"- {line}" for line in result["checks"]) or "- none"
    tools = ", ".join(result["tools_called"]) or "none"
    return (f"Hypothesis: {result['hypothesis']}\nEvidence:\n{evidence}\nChecks:\n{checks}\n"
            f"Turns: {result['turns']}\nTools called: {tools}")


def parallel_diagnosis(agent, args, dry_run):
    focus = str(args.get("focus") or "").strip()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            "service": pool.submit(_model_specialist, agent, "service", focus, dry_run),
            "platform": pool.submit(_model_specialist, agent, "platform", focus, dry_run),
            "knowledge": pool.submit(_knowledge, agent, focus),
        }
        results = {}
        for role, future in futures.items():
            try:
                results[role] = future.result()
            except Exception as error:  # noqa: BROAD_EXCEPT_OK - one specialist must not hide the other views
                results[role] = {"role": role, "hypothesis": f"specialist unavailable: {type(error).__name__}: {error}",
                                 "evidence": [], "checks": [], "turns": 0, "tools_called": []}

    service, platform = results["service"], results["platform"]
    same = " ".join(service["hypothesis"].lower().split()) == " ".join(platform["hypothesis"].lower().split())
    if same:
        agreement = f"- {service['hypothesis']}"
        conflict = "- none"
    else:
        agreement = "- none"
        conflict = f"- service: {service['hypothesis']}\n- platform: {platform['hypothesis']}"
    checks = list(dict.fromkeys(service["checks"] + platform["checks"] + results["knowledge"]["checks"]))
    merged_checks = "\n".join(f"- {check}" for check in checks) or "- none"
    sections = [
        ("## service specialist", _section(service)),
        ("## platform specialist", _section(platform)),
        ("## knowledge", _section(results["knowledge"])),
        ("## merge", f"Agreeing hypotheses:\n{agreement}\nConflicting hypotheses:\n{conflict}\n"
                     f"Recommended checks:\n{merged_checks}"),
    ]
    health = agent.with_health("")
    health = health[1:] if health.startswith("\n") else health
    health = health[:1200]
    suffix = f"\n{health}\n{CLOSING}"
    budget = max(0, LIMIT - len(suffix))
    body = "\n\n".join(f"{heading}\n{content}" for heading, content in sections)
    if len(body) > budget:
        fixed = sum(len(heading) + 1 for heading, _ in sections) + 6
        quota = max(0, (budget - fixed) // len(sections))
        body = "\n\n".join(f"{heading}\n{content[:quota]}" for heading, content in sections)
    return body + suffix
