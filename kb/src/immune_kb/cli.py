from __future__ import annotations

import argparse
import json
import platform
import shutil
import sqlite3
import sys
from importlib import resources
from pathlib import Path

from .api import KnowledgeBase
from .compression import compress_events
from .corpus import write_case_corpus, write_topology_corpus
from .evidence import find_eval_truth, load_evidence
from .evaluation import prepare_evaluation, score_predictions
from .rag import export_rag_corpus
from .resources import default_database_path, default_rag_corpus_path
from .store import build_database, database_stats


def _solutions_resource() -> Path:
    resource = resources.files("immune_kb").joinpath("data/solutions.json")
    return Path(str(resource))


def command_build(args: argparse.Namespace) -> int:
    datasets_root = Path(args.datasets_root).resolve()
    output_dir = Path(args.out_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    counts = write_case_corpus(datasets_root, output_dir)
    topology_count = write_topology_corpus(datasets_root, output_dir)
    solutions_output = output_dir / "solutions.json"
    shutil.copyfile(_solutions_resource(), solutions_output)
    database = output_dir / "immune_kb.sqlite"
    indexed = build_database(
        database,
        output_dir / "cases_train.jsonl",
        solutions_output,
        output_dir / "topologies.jsonl",
    )
    rag_report = export_rag_corpus(database, output_dir / "rag_documents.jsonl")
    (output_dir / "rag_manifest.json").write_text(
        json.dumps(rag_report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "database": str(database),
                "case_splits": counts,
                "indexed": indexed,
                "topology_documents": topology_count,
                "rag": rag_report,
                "rule": "Only train cases and curated solutions are indexed; dev/eval labels stay outside DB.",
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def command_search(args: argparse.Namespace) -> int:
    kb = KnowledgeBase(args.db)
    result = kb.search(
        args.query,
        scenario=args.scenario,
        doc_type=args.doc_type,
        top_k=args.top_k,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def command_context(args: argparse.Namespace) -> int:
    kb = KnowledgeBase(args.db)
    if args.incident == "-":
        incident = json.load(sys.stdin)
    else:
        incident = json.loads(Path(args.incident).read_text(encoding="utf-8"))
    print(
        json.dumps(
            kb.retrieve(
                incident,
                case_k=args.case_k,
                solution_k=args.solution_k,
                minimum_solution_coverage=args.minimum_solution_coverage,
            ),
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


def command_stats(args: argparse.Namespace) -> int:
    database = Path(args.db) if args.db else default_database_path()
    print(json.dumps(database_stats(database), ensure_ascii=False, indent=2))
    return 0


def command_export_rag(args: argparse.Namespace) -> int:
    database = Path(args.db) if args.db else default_database_path()
    report = export_rag_corpus(database, args.out)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def command_doctor(args: argparse.Namespace) -> int:
    database = Path(args.db) if args.db else default_database_path()
    stats = database_stats(database)
    connection = sqlite3.connect(database)
    try:
        fts5 = connection.execute("SELECT COUNT(*) FROM documents_fts").fetchone()[0] > 0
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        connection.close()
    try:
        rag_path = default_rag_corpus_path()
        rag_available = rag_path.is_file()
        rag_documents = sum(1 for line in rag_path.read_text(encoding="utf-8").splitlines() if line)
    except FileNotFoundError:
        rag_path = None
        rag_available = False
        rag_documents = 0
    rag_matches_database = rag_documents == stats["documents"]
    report = {
        "status": "pass" if fts5 and integrity == "ok" and rag_available and rag_matches_database else "fail",
        "python": platform.python_version(),
        "system": platform.system(),
        "machine": platform.machine(),
        "sqlite": sqlite3.sqlite_version,
        "fts5": fts5,
        "integrity": integrity,
        "database": str(database.resolve()),
        "packaged_rag": str(rag_path) if rag_path else None,
        "rag_available": rag_available,
        "rag_documents": rag_documents,
        "rag_matches_database": rag_matches_database,
        "stats": stats,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "pass" else 1


def command_materialize(args: argparse.Namespace) -> int:
    truth = find_eval_truth(args.ground_truth, args.eval_id)
    evidence = load_evidence(truth, args.datasets_root, max_events=args.max_events)
    compressed = compress_events(
        evidence["events"],
        target_ratio=args.ratio,
        keywords=args.keyword,
        window_start=evidence.get("window", {}).get("start"),
        window_end=evidence.get("window", {}).get("end"),
    )
    payload = {
        "id": args.eval_id,
        "compression_ratio": args.ratio,
        "telemetry": compressed["events"],
        "compression_metrics": compressed["metrics"],
    }
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output.resolve()), "metrics": compressed["metrics"]}, ensure_ascii=False, indent=2))
    return 0


def command_prepare_eval(args: argparse.Namespace) -> int:
    ratios = [float(value) for value in args.ratios.split(",") if value.strip()]
    report = prepare_evaluation(
        args.ground_truth,
        args.datasets_root,
        args.out_dir,
        ratios=ratios,
        limit=args.limit,
        scenario=args.scenario,
        source=args.source,
        max_events=args.max_events,
        keywords=args.keyword,
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def command_score(args: argparse.Namespace) -> int:
    report = score_predictions(args.ground_truth, args.predictions, args.out)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="immune-kb", description="IMMUNE offline case + solution KB")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="Normalize downloaded datasets and build offline SQLite index")
    build.add_argument("--datasets-root", default="datasets/raw")
    build.add_argument("--out-dir", default="immune_kb/artifacts")
    build.set_defaults(func=command_build)

    search = subparsers.add_parser("search", help="Search cases or solutions")
    search.add_argument("--db", help="SQLite path; omit to use packaged Linux RAG database")
    search.add_argument("--query", required=True)
    search.add_argument("--scenario", choices=("disk_full", "crashloop", "dns", "other"))
    search.add_argument("--doc-type", choices=("case", "solution", "topology"))
    search.add_argument("--top-k", type=int, default=5)
    search.set_defaults(func=command_search)

    context = subparsers.add_parser("context", help="Retrieve case + solution context for one incident JSON")
    context.add_argument("--db", help="SQLite path; omit to use packaged Linux RAG database")
    context.add_argument("--incident", required=True, help="Incident JSON path, or - for stdin")
    context.add_argument("--case-k", type=int, default=4)
    context.add_argument("--solution-k", type=int, default=4)
    context.add_argument("--minimum-solution-coverage", type=float, default=0.34)
    context.set_defaults(func=command_context)

    stats = subparsers.add_parser("stats", help="Show indexed document counts")
    stats.add_argument("--db", help="SQLite path; omit to use packaged Linux RAG database")
    stats.set_defaults(func=command_stats)

    export = subparsers.add_parser("export-rag", help="Export portable id/text/metadata JSONL for vector RAG")
    export.add_argument("--db", help="SQLite path; omit to use packaged Linux RAG database")
    export.add_argument("--out", required=True)
    export.set_defaults(func=command_export_rag)

    doctor = subparsers.add_parser("doctor", help="Verify the Linux runtime, SQLite FTS5, and packaged RAG data")
    doctor.add_argument("--db", help="SQLite path; omit to use packaged Linux RAG database")
    doctor.set_defaults(func=command_doctor)

    materialize = subparsers.add_parser("materialize", help="Load and compress raw telemetry for one held-out case")
    materialize.add_argument("--ground-truth", default="immune_kb/artifacts/eval_ground_truth.jsonl")
    materialize.add_argument("--datasets-root", default="datasets/raw")
    materialize.add_argument("--eval-id", required=True)
    materialize.add_argument("--ratio", type=float, default=4.0)
    materialize.add_argument("--keyword", action="append", default=[])
    materialize.add_argument("--max-events", type=int, default=2000)
    materialize.add_argument("--out", required=True)
    materialize.set_defaults(func=command_materialize)

    prepare = subparsers.add_parser("prepare-eval", help="Create label-free telemetry inputs at several compression ratios")
    prepare.add_argument("--ground-truth", default="immune_kb/artifacts/eval_ground_truth.jsonl")
    prepare.add_argument("--datasets-root", default="datasets/raw")
    prepare.add_argument("--out-dir", required=True)
    prepare.add_argument("--ratios", default="1,2,4,8")
    prepare.add_argument("--limit", type=int, default=10)
    prepare.add_argument("--scenario", choices=("disk_full", "crashloop", "dns", "other"))
    prepare.add_argument("--source")
    prepare.add_argument("--keyword", action="append", default=[])
    prepare.add_argument("--max-events", type=int, default=2000)
    prepare.set_defaults(func=command_prepare_eval)

    score = subparsers.add_parser("score", help="Score model predictions and emit compression-vs-accuracy curve CSV")
    score.add_argument("--ground-truth", default="immune_kb/artifacts/eval_ground_truth.jsonl")
    score.add_argument("--predictions", required=True)
    score.add_argument("--out", required=True)
    score.set_defaults(func=command_score)
    return parser


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    return args.func(args)
