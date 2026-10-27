# IMMUNE

**Autonomous Infrastructure Immune System**

> Infrastructure that can observe, diagnose, recover, and verify itself.

**English** | [繁體中文](README.zh-TW.md)

| OBSERVE | DIAGNOSE | RECOVER | VERIFY |
|---|---|---|---|
| Reads health, logs and state | Finds the likely cause from evidence | Applies the smallest allowed fix | Confirms that health really came back |

**LOCAL-FIRST · SELF-HEALING · POLICY-GOVERNED**

IMMUNE is a local recovery agent that sits next to your infrastructure. When something breaks, it closes the loop from detection to a verified recovery on its own. Every action goes through policy, and every step is recorded.

**Status: Stage I competition proposal.** IMMUNE builds on a working recovery-agent prototype. This README keeps what exists today and what is proposed in separate sections, so no planned feature reads as finished.

- Proposal deck: [`proposal/IMMUNE-proposal.pdf`](proposal/IMMUNE-proposal.pdf).
- Core code of the working prototype: the recovery loop, safety gates, knowledge layers and fault-injection bench. See [What this repository contains](#what-this-repository-contains).

---

## Contents

1. [Why IMMUNE](#why-immune)
2. [How It Works](#how-it-works)
3. [Architecture](#architecture)
4. [Safety Model](#safety-model)
5. [Local Intelligence](#local-intelligence)
6. [Recovery Loop](#recovery-loop)
7. [Evaluation](#evaluation)
8. [Prototype](#prototype)
9. [Development Roadmap](#development-roadmap)
10. [Technical Details](#technical-details)

---

## Why IMMUNE

Modern infrastructure is good at noticing failure: monitoring raises alerts within seconds. Recovery is still a person's job. Someone reads the alert, gets woken up, digs through logs and documentation, tries commands, checks the result and goes around again. Every incident becomes a human debugging loop, and it is slowest at the hours when nobody is awake.

The tools people lean on during that loop often live somewhere else: cloud AI assistants, SaaS observability, remote documentation. In a serious outage the network and those services can fail along with the system itself.

IMMUNE gives infrastructure its own immune system. A local agent watches the systems it protects, works out what went wrong, applies a fix it is allowed to apply, and checks that health really came back. If the fix did not hold, it plans again. It does all of this on site, inside explicit policy boundaries, and leaves a complete audit trail.

---

## How It Works

The immune system is a metaphor for the loop, not a medical product. Each part of the loop has a direct counterpart:

| Immune system | IMMUNE | What happens |
|---|---|---|
| Signals | Telemetry and logs | Health checks, container state and service logs are collected continuously |
| Sensing | Incident detection | An incident opens after repeated abnormal checks, so a single blip does not page |
| Recognition | Diagnosis | The agent gathers evidence with read-only tools and identifies the likely cause |
| Memory | Knowledge retrieval | Runbooks, fixes that worked before, and community answers are attached to the evidence |
| Response | Recovery planning | The agent chooses the smallest fix that addresses the cause |
| Safety boundary | Policy | Allowed actions run; destructive ones are blocked; risky ones wait for a person |
| Immune action | Execution | A named, allow-listed action runs; there is no free-form shell |
| Recovery check | Verification | Status code **and** page content must both be correct |
| Adaptive response | Re-planning | If health is not restored, the agent plans again |

---

## Architecture

![IMMUNE system architecture: health probes, an incident detector and triage sense failures in the infrastructure; a sandboxed recovery agent reasons over knowledge and incident memory through a local inference gateway; policy gates, an allow-listed tool gateway and action adapters run the fix; a verifier closes the incident or sends it back for re-planning, and verified fixes become incident memory; every event goes to the audit trail](assets/immune-system-architecture.drawio.svg)

Solid boxes are built today; dashed boxes are planned for the competition. The numbers follow one incident:

1. **Signals.** Health probes check status and page content; the detector opens an incident after repeated failures.
2. **Incident with evidence.** Triage attaches signals and opening evidence and hands the incident to the recovery agent.
3. **Reason and retrieve.** The sandboxed agent investigates. Retrieval ranks knowledge and incident memory, and a judge withholds off-topic references. Reasoning goes through a local OpenAI-compatible gateway, so the serving engine and model can be swapped.
4. **Proposed action.** The agent can only propose. Policy gates allow it, block it, or ask a human in the operator console.
5. **Allowed action.** The tool gateway runs named, allow-listed actions through adapters. There is no shell.
6. **Verify.** The verifier checks status and page content: pass closes the incident, fail sends it back for re-planning.
7. **Memory.** A verified fix is recorded in incident memory and is offered first the next time the same symptom appears.

Every signal, decision, approval and action is appended to the audit trail, which the operator console can replay.

| Region | Components | Role |
|---|---|---|
| Infrastructure | Services and containers today; servers and VMs, AI nodes and edge sites planned | What IMMUNE protects |
| Sense | Health probes, incident detector, triage | Turn a failure into an incident with evidence |
| Decide | Recovery agent; retrieval and judge over knowledge and incident memory; local inference gateway and runtime | Find the cause and propose a fix |
| Act safely | Policy gates, tool gateway, action adapters, verifier | Run only allowed actions, then check the result |
| Record | Audit trail, operator console | Keep every event; human approval and replay |

Both architecture diagrams are editable draw.io files: open [`assets/immune-system-architecture.drawio.svg`](assets/immune-system-architecture.drawio.svg) or [`assets/immune-architecture.drawio.svg`](assets/immune-architecture.drawio.svg) in draw.io (diagrams.net).

### Current prototype vs. target architecture

The target architecture is hardware-agnostic. The current prototype is not yet: its inference backend runs on an NVIDIA GPU. The prototype does already separate the agent from the model behind one OpenAI-compatible endpoint, and that separation is the starting point for portability.

| Layer | Current prototype (implemented) | Target architecture (proposed) |
|---|---|---|
| Infrastructure | Two containerized web services (front end and API) as the test target; 50 injectable faults | Servers, VMs, systemd services, Kubernetes workloads, AI nodes |
| Observe | HTTP status and page-content probe every 2 s, container state, service logs | Plus metrics, log and event integrations |
| Diagnose and plan | Local agent in a sandbox, gathering evidence through allow-listed read-only tools | Same loop with richer signals |
| Knowledge | Incident memory, 16 runbooks, repair cards, 158,881 community answers, rerank and a local judge | Site-specific knowledge; measured end-to-end benefit |
| Policy | Allow-list, runbook gate, guardrails, two-key reviewer, human approval, repair before replace | Declarative policy engine; dry-run preview for every action |
| Recover | Container and web-server configuration actions | Action adapters for systemd, VMs and Kubernetes |
| Verify | Status and page content after every action | Service-level health checks |
| Audit | Tool-call log, agent trajectories, reviewer verdicts, approvals, incident log, dashboard replay | Exportable audit reports |
| Local AI compute | One OpenAI-compatible endpoint; today's backend is vLLM on an NVIDIA GPU | Hardware abstraction layer; runtime chosen for the available accelerator |

---

## Safety Model

**Autonomous does not mean unrestricted.** The model proposes; deterministic systems decide what is allowed.

```
AI decision → policy validation → allow-listed action → execution boundary → verification → audit
```

| Boundary | What it does |
|---|---|
| Allow-listed actions | The agent can call only named actions from an allow-list. It has no shell, and destructive tools are never offered to it. |
| Evidence gate | Before changing anything, the agent must have read the matching runbook or evidence. |
| Guardrails | Instruction-like text in tool output is removed, and actions that follow injected text are refused. |
| Two-key review | For risky actions, code first checks the precondition; a second model then checks relevance and contradictions. If the reviewer is unreachable, nothing runs. |
| Human approval | Rebuild-type actions wait for a person on the dashboard. A rejection makes the agent choose another path. |
| Repair before replace | A container cannot be replaced while a repairable file is still broken. |
| Verification | After every action, status code and page content are both checked. |
| Audit | Every tool call, decision, verdict and approval is logged and can be replayed. |

**Prototype evidence.** Commands planted in service logs and config files were blocked in every test: 2 of 2 on the development workstation and 3 of 3 on the prototype device. No destructive action ran in any measured run.

**Why page content matters.** "200 OK" does not mean fixed. The prototype caught two real cases: an injected fault that served the wrong page with status 200, and the agent itself writing a placeholder page to make a health check pass. A status-only check would have recorded both as recovered.

---

## Local Intelligence

IMMUNE keeps reasoning, knowledge and actions on site. Logs and data never leave, and recovery keeps working when the wide-area network is down.

**Local reasoning model.** The agent talks to one OpenAI-compatible endpoint, so the model and serving runtime can be replaced without touching the agent. During development, the prototype used two serving engines and four different models behind that endpoint without changing the agent layer.

**Knowledge is pushed, not pulled.** When the model had to look things up on its own, it did so once in 70 runs. The prototype therefore attaches knowledge next to the evidence, nearest first:

1. **Incident memory.** Fixes this site has verified itself, written only after a green verification.
2. **Runbooks.** Standard procedures for the stack, retrieved by meaning.
3. **Repair cards.** Fixes written for the available tools, offered only when the symptom matches.
4. **Community answers.** 158,881 accepted answers from operations Q&A sites, searched with SQLite full-text search.
5. **Rerank and judge.** A reranker orders the candidates, and a local model withholds anything off-topic, because a wrong reference is worse than none.

| Retrieval measurement (prototype, held-out data) | Result |
|---|---|
| First-stage recall@50 (1,139 held-out questions) | 0.99 |
| Top-1 answer judged truly relevant | 6% with keyword search, 13% after rerank |
| 38 real datacenter error messages, top-5 on topic | 71% |

---

## Recovery Loop

![IMMUNE closed loop: infrastructure feeds signals into observe, diagnose, plan, recover and verify, which draws on knowledge and policy, runs on local AI compute, and writes an audit trail](assets/immune-architecture.drawio.svg)

1. **Detect.** A watchdog checks status and page content every 2 seconds and opens an incident after two consecutive failures.
2. **Opening evidence.** Health, container state and service logs are attached to the incident.
3. **Investigate.** The agent inspects state with read-only tools.
4. **Knowledge.** Runbooks, past recoveries and community references are attached next to the evidence.
5. **Act within policy.** The proposed action passes the safety boundaries above.
6. **Verify.** Status and content are checked after every action.
7. **Close or re-plan.** Green closes the incident and records the fix in incident memory; red sends the agent back to planning.

The loop covers four kinds of autonomy: re-planning when a fix exposes the next problem, choosing an alternative when a human rejects an action, retrying when verification fails, and verifying every step.

**Repair before replace.** Rebuilding a service can turn a test green while hiding the cause. The prototype restores the broken file or reverts the one bad line, validates the configuration, reloads and checks content. On the prototype device, backend configuration and content faults were repaired 3 of 3 times with 0 container replacements.

---

## Evaluation

IMMUNE is measured on recovery outcomes, not model accuracy.

| KPI | Direction | Prototype baseline | Competition evaluation plan |
|---|---|---|---|
| MTTD, time to detect | ↓ | ≈4 s from fault to incident | Same metric on the competition hardware |
| MTTR, time to recover | ↓ | 32–85 s for the three demo faults; fastest single fault 14 s | Side by side with manual operations on the same failures |
| Recovery rate | ↑ | 85%: 23 of 27 runs without a human | Larger set of blind scenarios |
| Human intervention | ↓ | Approval only for rebuild-type actions | Counted per incident |
| Unsafe action rate | → 0 | 0 destructive actions, 0 runs made worse | Held at 0 under adversarial faults |
| Cloud dependency | none | Runs without WAN or cloud connectivity | Verified with the WAN cut |

No manual-operations comparison has been run yet. That baseline is part of the competition plan, and no comparison figure is claimed here.

**Definitions used for the prototype numbers**

| Term | Definition |
|---|---|
| Success | Both health URLs return 200 **and** serve the correct page content |
| Autonomous recovery | Success with no human help and no fallback mechanism before recovery |
| Made worse | A URL that was alive when the fault was injected is dead at the end |
| False "healthy" claim | The agent reports a fix, but the health check fails |
| Incident time | From the incident opening until both URLs are green |

---

## Prototype

### Implemented today

| Capability | Where it lives |
|---|---|
| Local agent loop with an OpenAI-compatible model endpoint | [`scripts/agent.py`](scripts/agent.py), [`scripts/oai_shim.py`](scripts/oai_shim.py) |
| Incident detection with a 2-second patrol | [`scripts/watchdog.py`](scripts/watchdog.py), [`scripts/triage.py`](scripts/triage.py) |
| Allow-listed tool execution, no shell | [`scripts/ops_api.py`](scripts/ops_api.py), [`scripts/agent.py`](scripts/agent.py) |
| Knowledge retrieval and incident memory | [`scripts/rag.py`](scripts/rag.py), [`scripts/community_knowledge.py`](scripts/community_knowledge.py), [`scripts/incident_memory.py`](scripts/incident_memory.py), [`runbooks/`](runbooks/) |
| Guardrails, two-key review, human approval | [`scripts/guard_api.py`](scripts/guard_api.py), [`scripts/reviewer.py`](scripts/reviewer.py), [`scripts/approval.py`](scripts/approval.py) |
| Repair before replace, configuration validation | [`scripts/agent.py`](scripts/agent.py) |
| Verification of status and page content | [`scripts/agent.py`](scripts/agent.py) |
| Audit trail | agent trajectories and tool-call log written to `logs/` |
| Fault-injection bench, 50 failures in 8 classes | [`scripts/faults.py`](scripts/faults.py) |
| Scoring harness | [`scripts/score.py`](scripts/score.py) |

The prototype also has an operator dashboard with replay, a network-cut switch, an energy meter, deployment scripts and a two-container test stack. They are not published in this repository.

### Measured results

Measured in the prototype's local test environment: two containerized web services on one edge AI device, and a development workstation for larger batches.

| Result | Value | Where |
|---|---|---|
| Autonomous recovery | **23 of 27 runs (85%)**, covering 15 of the 50 catalogued fault scenarios; every one of the 15 recovered at least once | prototype device |
| Runs made worse / false "healthy" claims | **0 / 0** | prototype device |
| Fault to incident | ≈4 s | prototype device |
| Fastest recovery | 14 s | prototype device |
| Three demo faults, incident to green | 32–85 s | prototype device |
| Repair without replacing containers | 3 of 3 | prototype device |
| Hardest fault (worker file-descriptor limit) | 0 of 5 before a targeted runbook and tool; 64 s and 3 tool calls after | prototype device |
| Full-catalogue regression | 30 of 32 autonomous | development workstation |
| Blind faults, written after tuning | 17 of 18 on the first pass; the remaining one passed 2 of 2 after a tool fix | development workstation |
| Local model serving | 49.6 tokens/s, 0.53 s to first token | prototype device |
| Memory and power for the whole stack | ≈46 GB, no swap; ≈74 W under load | prototype device |

### Known limitations

- One fault, a backend bound only to the loopback address, was recovered once and missed once.
- Community retrieval improved relevance, but its end-to-end effect on recovery is not proven.
- The test target is two containers; real servers, VMs and network equipment are not yet action targets.
- Scripts for a VM target exist but were never run on hardware.
- The inference backend currently requires an NVIDIA GPU.
- Prototype services have no authentication and belong on an isolated network.

---

## Development Roadmap

### Proposed for the competition

| Work item | Goal |
|---|---|
| Hardware-agnostic runtime | A hardware abstraction layer under the OpenAI-compatible endpoint, ported to the competition accelerator |
| Expanded failure scenarios | VMs, systemd services, Kubernetes workloads and AI nodes, beyond the two-container test bench |
| Stronger safety policies | A declarative policy engine and a dry-run preview for every action |
| Evaluation framework | MTTD, MTTR, recovery rate, human intervention and unsafe actions, measured against manual operations |
| Production-oriented UX | Incident view, approvals and audit reports built for operators |
| Observability integrations | Metrics, log and event sources beyond direct health probes |

### Future work

- Fleet and multi-site deployment.
- Signed, exportable audit records.
- Action adapters for network equipment and out-of-band management.
- Standard benchmark runs that need a Kubernetes cluster.
- Authentication and access control for every service.

---

## Technical Details

### Current implementation

The system architecture is shown [above](#architecture). Today's prototype runs on one edge AI device. The agent runs in a sandbox and reaches the model only through an OpenAI-compatible endpoint. Today's serving backend is vLLM with a quantized open model on an NVIDIA GPU. In deployment the monitored system is a separate host; in the prototype benchmark the test containers ran on the same device.

| Component | Role | Code |
|---|---|---|
| Watchdog and triage | Patrol, incident opening, opening evidence | [`scripts/watchdog.py`](scripts/watchdog.py), [`scripts/triage.py`](scripts/triage.py) |
| Agent instructions | Operating rules for the sandboxed agent that plans and calls tools | [`skills/ops/SKILL.md`](skills/ops/SKILL.md) |
| Model endpoint | OpenAI-compatible layer in front of the serving runtime | [`scripts/oai_shim.py`](scripts/oai_shim.py) |
| Tool layer | Allow-listed actions, evidence gate, verification, knowledge push | [`scripts/ops_api.py`](scripts/ops_api.py), [`scripts/agent.py`](scripts/agent.py) |
| Safety gates | Guardrails, reviewer, human approval | [`nemo/`](nemo/), [`scripts/guard_api.py`](scripts/guard_api.py), [`scripts/reviewer.py`](scripts/reviewer.py), [`scripts/approval.py`](scripts/approval.py) |
| Knowledge | Runbooks, repair cards, community answers, incident memory | [`runbooks/`](runbooks/), [`kb/`](kb/), [`scripts/community_knowledge.py`](scripts/community_knowledge.py), [`scripts/incident_memory.py`](scripts/incident_memory.py) |
| Test bench | Fault injection and scoring | [`scripts/faults.py`](scripts/faults.py), [`scripts/score.py`](scripts/score.py) |

### What this repository contains

This repository publishes the concept and the core code of the prototype: the recovery loop, the tool layer, safety gates, knowledge retrieval, incident memory and the fault-injection bench.

Not included: deployment and start scripts, model serving scripts, the agent sandbox configuration, the operator dashboard, the two-container test stack, and the knowledge corpora and indexes. Without them the code does not run end to end; the unit tests run on their own.

Tests run with:

```bash
uv run --no-project --with pytest python -m pytest tests -q
```

On a machine without Docker and the test stack, 4 host-dispatch tests fail and the other 120 pass.

### Repository layout

```
scripts/      agent loop, tool API, watchdog, safety gates, knowledge retrieval, fault injection, scoring
runbooks/     standard procedures the agent retrieves
kb/           knowledge-base package (code only) and repair cards
nemo/         guardrail configuration
skills/ops/   operating instructions for the agent
tests/        unit tests
assets/       architecture diagrams, editable in draw.io
proposal/     competition deck (PDF)
```

### Data sources and licenses

| Data | Use | License |
|---|---|---|
| Stack Exchange operations sites (158,881 accepted answers) | Community knowledge; each record keeps its question, author, revision and link | CC BY-SA |
| AgenticOpsEval (AIOps2025 + RCA100) | Offline root-cause evaluation; raw data not committed | CC BY-NC 4.0; CC BY-NC-SA 4.0 |
| Cloud-OpsBench, RCAEval | Offline evaluation and failure-pattern reference | MIT |
| ITBench-Lite | CrashLoopBackOff case reference | Apache-2.0 |
| Kubernetes and systemd documentation | Checks and safety limits in repair cards | Their own licenses |
| Language and reranking models, agent runtime, guardrails | Inference, sandbox, guardrails | Each under its publisher's license |
| Lucide icons, Simple Icons | Icons in the diagrams; product logos belong to their owners | ISC; CC0 |

Knowledge corpora and indexes, raw public datasets, model weights and logs are not in this repository.

The code and documents in this repository are released under the [MIT License](LICENSE). Third-party data, models and icons keep the licenses listed above. Evaluation answers never enter the retrieval index.
