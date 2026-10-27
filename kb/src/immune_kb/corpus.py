from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any


def stable_split(case_id: str) -> str:
    """Stable 80/10/10 split. Eval labels never enter search index."""
    bucket = int(hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:8], 16) % 10
    if bucket == 0:
        return "eval"
    if bucket == 1:
        return "dev"
    return "train"


def infer_scenario(*values: Any) -> str:
    text = " ".join(str(v) for v in values if v is not None).lower()
    if any(term in text for term in ("dns", "name resolution", "no such host", "網域解析", "名稱解析")):
        return "dns"
    if any(
        term in text
        for term in ("disk", "no space left", "filesystem", "file_write", "file write", "磁碟", "硬碟", "空間不足")
    ):
        return "disk_full"
    if any(
        term in text
        for term in (
            "crashloop",
            "pod failure",
            "pod kill",
            "oomkilled",
            "oom killed",
            "invalid command",
            "container_memory_limit",
            "反覆重啟",
            "容器重啟",
            "當機迴圈",
        )
    ):
        return "crashloop"
    return "other"


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _record(
    *,
    case_id: str,
    title: str,
    scenario: str,
    content: str,
    tags: Iterable[str],
    source: str,
    source_path: str,
    metadata: dict[str, Any],
    labels: Iterable[str] = (),
    platform: str = "kubernetes",
) -> dict[str, Any]:
    return {
        "id": case_id,
        "doc_type": "case",
        "scenario": scenario,
        "platform": platform,
        "title": title,
        "content": content,
        "tags": sorted({str(tag) for tag in tags if tag}),
        "source": source,
        "source_path": source_path.replace("\\", "/"),
        "split": stable_split(case_id),
        "risk_tier": None,
        "labels": sorted({str(label) for label in labels if label}),
        "metadata": metadata,
    }


def iter_aiops2025(root: Path) -> Iterator[dict[str, Any]]:
    path = root / "AgenticOpsEval" / "AIOps2025" / "groundtruth.jsonl"
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            item = json.loads(line)
            uid = str(item.get("uuid", "unknown"))
            fault = str(item.get("fault_type", "unknown"))
            service = _text(item.get("service"))
            descriptions = item.get("fault_description") or []
            observations = item.get("key_observations") or []
            evidence = []
            for observation in observations:
                evidence.append(
                    " ".join(
                        part
                        for part in (
                            str(observation.get("type", "")),
                            str(observation.get("subtype", "")),
                            " ".join(observation.get("keyword") or []),
                        )
                        if part
                    )
                )
            scenario = infer_scenario(fault, descriptions)
            content = "\n".join(
                (
                    f"Fault: {fault}",
                    f"Service: {service}",
                    f"Symptoms: {'; '.join(descriptions)}",
                    f"Key evidence: {'; '.join(evidence)}",
                    f"Time window: {item.get('start_time', '')} to {item.get('end_time', '')}",
                )
            )
            yield _record(
                case_id=f"agentic-aiops2025-{uid}",
                title=f"{fault} on {service or 'unknown service'}",
                scenario=scenario,
                content=content,
                tags=(fault, service, item.get("fault_category", ""), item.get("instance_type", "")),
                source="AgenticOpsEval/AIOps2025",
                source_path=str(path.relative_to(root)),
                metadata={
                    "uuid": uid,
                    "fault_type": fault,
                    "fault_category": item.get("fault_category"),
                    "service": item.get("service"),
                    "instance": item.get("instance"),
                    "key_metrics": item.get("key_metrics") or [],
                    "start_time": item.get("start_time"),
                    "end_time": item.get("end_time"),
                },
                labels=(fault,),
            )


def iter_rca100(root: Path) -> Iterator[dict[str, Any]]:
    answer_root = root / "AgenticOpsEval" / "RCA100" / "answer_key"
    if not answer_root.exists():
        return
    for path in sorted(answer_root.glob("*.gt.json")):
        item = json.loads(path.read_text(encoding="utf-8"))
        fault_types = item.get("root_cause_types") or []
        entities = item.get("root_cause_entities") or []
        conclusion = ""
        reasoning: list[str] = []
        raw = item.get("raw_ground_truth")
        if raw:
            try:
                parsed = json.loads(raw)
                conclusion = parsed.get("outcome", {}).get("expected_conclusion", "")
                reasoning = [
                    step.get("description", "")
                    for step in parsed.get("reasoning", {}).get("steps", [])
                    if step.get("description")
                ]
            except json.JSONDecodeError:
                conclusion = str(raw)[:2000]
        scenario = infer_scenario(fault_types, conclusion)
        content = "\n".join(
            (
                f"Alert: {item.get('alert_title', '')}",
                f"Root cause types: {', '.join(fault_types)}",
                f"Root cause entities: {', '.join(entities)}",
                f"Conclusion: {conclusion}",
                "Causal evidence: " + " | ".join(reasoning),
            )
        )
        case_name = path.stem.removesuffix(".gt")
        yield _record(
            case_id=f"agentic-rca100-{case_name}",
            title=f"{'/'.join(fault_types) or 'unknown fault'} on {','.join(entities) or 'unknown entity'}",
            scenario=scenario,
            content=content,
            tags=(*fault_types, *entities, "causal-chain"),
            source="AgenticOpsEval/RCA100",
            source_path=str(path.relative_to(root)),
            metadata={
                "task_id": case_name,
                "incident_id": item.get("incident_id"),
                "fault_types": fault_types,
                "entities": entities,
                "time_start": item.get("time_range_start"),
                "time_end": item.get("time_range_end"),
            },
            labels=fault_types,
        )


def iter_cloud_ops(root: Path) -> Iterator[dict[str, Any]]:
    repo = root / "Cloud-OpsBench"
    benchmark = repo / "benchmark"
    if not benchmark.exists():
        return
    for path in sorted(benchmark.rglob("metadata.json")):
        item = json.loads(path.read_text(encoding="utf-8"))
        relative_case = path.parent.relative_to(benchmark)
        result = item.get("result") or {}
        cause = str(result.get("root_cause", "unknown"))
        fault_object = str(result.get("fault_object", ""))
        milestone_path = repo / "process-label" / relative_case / "milestone.json"
        roles: list[str] = []
        tools: list[str] = []
        if milestone_path.exists():
            milestone = json.loads(milestone_path.read_text(encoding="utf-8"))
            for step in milestone.get("milestones") or []:
                roles.append(str(step.get("role", "")))
                tools.extend(
                    str(call.get("tool_name", ""))
                    for call in step.get("admissible_tool_uses") or []
                    if call.get("tool_name")
                )
        golden_path = repo / "golden-trajectory" / relative_case / "path1.json"
        golden_calls: list[str] = []
        if golden_path.exists():
            golden = json.loads(golden_path.read_text(encoding="utf-8"))
            golden_calls = [
                str(step.get("calling") or step.get("tool_name") or "")
                for step in golden.get("diagnostic_trace") or []
            ]
        scenario = infer_scenario(cause, item.get("query"))
        content = "\n".join(
            (
                f"Symptom: {item.get('query', '')}",
                f"Root cause: {cause}",
                f"Fault object: {fault_object}",
                f"Diagnostic milestones: {' -> '.join(filter(None, roles))}",
                f"Admissible tools: {', '.join(dict.fromkeys(filter(None, tools)))}",
                f"Example tool sequence: {' -> '.join(filter(None, golden_calls))}",
            )
        )
        case_key = str(relative_case).replace("\\", "-").replace("/", "-")
        yield _record(
            case_id=f"cloudops-{case_key}",
            title=f"{cause} affecting {fault_object or item.get('namespace', 'cluster')}",
            scenario=scenario,
            content=content,
            tags=(cause, fault_object, result.get("fault_taxonomy", ""), *roles, *tools),
            source="Cloud-OpsBench",
            source_path=str(path.relative_to(root)),
            metadata={
                "case": str(relative_case).replace("\\", "/"),
                "namespace": item.get("namespace"),
                "difficulty": item.get("difficulty"),
                "root_cause": cause,
                "fault_object": fault_object,
                "milestone_count": len(roles),
            },
            labels=(cause,),
        )


_RCA_EVAL_RE = re.compile(
    r"^(re[123])(ob|ss|tt)_(.+)_(cpu|mem|disk|delay|loss|socket|f[1-5])_(\d+)$"
)


def iter_rca_eval(root: Path) -> Iterator[dict[str, Any]]:
    repo = root / "RCAEval"
    if not repo.exists():
        return
    systems = {"ob": "Online Boutique", "ss": "Sock Shop", "tt": "Train Ticket"}
    for path in sorted((p for p in repo.iterdir() if p.is_dir()), key=lambda p: p.name):
        match = _RCA_EVAL_RE.match(path.name)
        if not match:
            continue
        suite, system_code, service, fault, repetition = match.groups()
        modalities = [name for name in ("metrics", "logs", "traces") if (path / f"{name}.parquet").exists()]
        scenario = infer_scenario(fault)
        content = "\n".join(
            (
                f"System: {systems[system_code]}",
                f"Suite: {suite.upper()}",
                f"Root cause service: {service}",
                f"Injected fault: {fault}",
                f"Available telemetry: {', '.join(modalities)}",
                "Injection boundary: inject_time.txt",
            )
        )
        yield _record(
            case_id=f"rcaeval-{path.name}",
            title=f"{fault} fault on {service} ({systems[system_code]})",
            scenario=scenario,
            content=content,
            tags=(suite, systems[system_code], service, fault, *modalities),
            source="RCAEval",
            source_path=str(path.relative_to(root)),
            metadata={
                "suite": suite.upper(),
                "system": systems[system_code],
                "root_cause_service": service,
                "fault": fault,
                "repetition": int(repetition),
                "modalities": modalities,
            },
            labels=(fault,),
        )


def iter_itbench(root: Path) -> Iterator[dict[str, Any]]:
    repo = root / "ITBench-Lite" / "snapshots" / "sre"
    if not repo.exists():
        return
    for path in sorted(repo.rglob("ground_truth.yaml")):
        raw = path.read_text(encoding="utf-8")
        lines = []
        mechanisms = []
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("fault_mechanism:"):
                mechanisms.append(stripped.partition(":")[2].strip())
            if stripped.startswith(("condition:", "description:", "effect:")):
                lines.append(stripped)
        scenario_name = path.parent.name
        scenario = infer_scenario(raw)
        content = "\n".join(
            (
                f"Scenario: {scenario_name}",
                f"Fault mechanisms: {', '.join(dict.fromkeys(mechanisms))}",
                "Ground-truth graph summary:",
                *lines[:80],
            )
        )
        selected_full = scenario_name in {"Scenario-12", "Scenario-105"}
        yield _record(
            case_id=f"itbench-{scenario_name.lower()}",
            title=f"ITBench {scenario_name}: {', '.join(dict.fromkeys(mechanisms)) or scenario}",
            scenario=scenario,
            content=content,
            tags=(scenario_name, *mechanisms, "full-snapshot" if selected_full else "metadata-only"),
            source="ITBench-Lite/SRE",
            source_path=str(path.relative_to(root)),
            metadata={
                "scenario_id": scenario_name,
                "fault_mechanisms": list(dict.fromkeys(mechanisms)),
                "full_snapshot_downloaded": selected_full,
            },
            labels=mechanisms or (scenario,),
        )


def iter_all_cases(root: Path) -> Iterator[dict[str, Any]]:
    readers = (iter_aiops2025, iter_rca100, iter_cloud_ops, iter_rca_eval, iter_itbench)
    for reader in readers:
        yield from reader(root)


def _opaque_eval_id(case_id: str) -> str:
    return "eval-" + hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:16]


def _eval_input(record: dict[str, Any]) -> dict[str, Any]:
    """Remove labels, label-bearing paths, titles, tags, and metadata from agent-visible eval input."""
    eval_id = _opaque_eval_id(record["id"])
    safe: dict[str, Any] = {
        "id": eval_id,
        "doc_type": "incident",
        "platform": record["platform"],
        "title": f"Held-out incident {eval_id}",
        "content": "Load raw telemetry through evaluator locator; no answer fields are present.",
        "source": record["source"],
        "split": "eval",
        "metadata": {},
    }
    metadata = record.get("metadata") or {}
    for key in ("time_start", "time_end", "start_time", "end_time", "modalities", "full_snapshot_downloaded"):
        if key in metadata:
            safe["metadata"][key] = metadata[key]
    return safe


def _eval_truth(record: dict[str, Any]) -> dict[str, Any]:
    """Evaluator-only locator and labels. Never indexed or sent to the diagnosing agent."""
    return {
        "id": _opaque_eval_id(record["id"]),
        "source_case_id": record["id"],
        "scenario": record["scenario"],
        "labels": record.get("labels") or [],
        "source": record["source"],
        "source_path": record["source_path"],
        "metadata": record.get("metadata") or {},
    }


def write_case_corpus(root: Path, output_dir: Path) -> dict[str, int]:
    output_dir.mkdir(parents=True, exist_ok=True)
    streams = {
        split: (output_dir / f"cases_{split}.jsonl").open("w", encoding="utf-8", newline="\n")
        for split in ("train", "dev", "eval")
    }
    truth_stream = (output_dir / "eval_ground_truth.jsonl").open("w", encoding="utf-8", newline="\n")
    counts = {"train": 0, "dev": 0, "eval": 0}
    try:
        for record in iter_all_cases(root):
            split = record["split"]
            output_record = _eval_input(record) if split == "eval" else record
            streams[split].write(json.dumps(output_record, ensure_ascii=False, separators=(",", ":")) + "\n")
            if split == "eval":
                truth_stream.write(json.dumps(_eval_truth(record), ensure_ascii=False, separators=(",", ":")) + "\n")
            counts[split] += 1
    finally:
        for stream in streams.values():
            stream.close()
        truth_stream.close()
    return counts


def write_topology_corpus(root: Path, output_dir: Path) -> int:
    """Extract unique service dependency graphs from RCA100 topology snapshots."""
    cases_root = root / "AgenticOpsEval" / "RCA100" / "cases"
    output = output_dir / "topologies.jsonl"
    seen: set[str] = set()
    count = 0
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        if not cases_root.exists():
            return 0
        for path in sorted(cases_root.glob("t*/topology.json")):
            item = json.loads(path.read_text(encoding="utf-8"))
            entities = {
                str(entity.get("id")): str(entity.get("name"))
                for entity in item.get("entities") or []
                if entity.get("type") == "apm.service" and entity.get("id") and entity.get("name")
            }
            dependencies = sorted(
                {
                    (entities[edge["src"]], entities[edge["dst"]])
                    for edge in item.get("edges") or []
                    if edge.get("relation") == "calls" and edge.get("src") in entities and edge.get("dst") in entities
                }
            )
            if not dependencies:
                continue
            signature = hashlib.sha256(json.dumps(dependencies).encode("utf-8")).hexdigest()
            if signature in seen:
                continue
            seen.add(signature)
            record = {
                "id": f"topology-rca100-{signature[:16]}",
                "doc_type": "topology",
                "scenario": "other",
                "platform": "kubernetes",
                "title": "RCA100 service dependency topology",
                "content": "\n".join(f"{source} calls {target}" for source, target in dependencies),
                "tags": sorted(set(entities.values())),
                "source": "AgenticOpsEval/RCA100",
                "source_path": str(path.relative_to(root)).replace("\\", "/"),
                "split": "knowledge",
                "risk_tier": None,
                "labels": [],
                "metadata": {
                    "services": len(entities),
                    "dependencies": len(dependencies),
                    "representative_case": path.parent.name,
                },
            }
            stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count
