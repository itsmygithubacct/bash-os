#!/usr/bin/env python3
"""Run the Docker parity case suite through scripts/docker-parity.py.

Every case is one runner invocation (`run` for a .sh case, `replay` for a
.replay.json case) against the two images' immutable IDs, resolved once at
the start. Results are classified against the known-differences file:

  pass   the runner reported a match
  fail   the runner reported a difference (or an error) and the case is not known
  xfail  a known difference that still differs, only in the declared ways
  xpass  a known difference that now matches: prune its entry

The exit status is 0 only when every selected case is a pass or an xfail.
"""
import argparse
import concurrent.futures
import datetime
import difflib
import fnmatch
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/docker-parity.py"
SUITE = ROOT / "tests/docker-parity/suite"
CATEGORIES = {
    "version-string": "a --version/--help text that does not claim to be GNU",
    "known-partial": "behaviour documented as a known partial implementation",
    "missing-tool": "a command that one image does not provide",
    "by-design": "a documented, deliberate bash-os behaviour",
    "environment": "an image difference outside the command (data files, locales)",
}
# Differences a known entry may declare; anything about the reference is never excusable.
ASPECTS = {"stdout", "stderr", "terminal", "exit status", "filesystem", "candidate"}
SIDE_CARS = (".stdin", ".status", ".args", ".timeout", ".fixture")
RESULTS = ("pass", "xfail", "fail", "xpass")


def load_runner():
    spec = importlib.util.spec_from_file_location("docker_parity", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def aspect(difference):
    """Map a runner difference line to the aspect a known entry can declare."""
    for name in ("stdout", "stderr", "terminal"):
        if difference.startswith(name + " bytes"):
            return name
    if difference == "exit status":
        return "exit status"
    if difference.startswith("filesystem"):
        return "filesystem"
    if difference == "candidate did not complete normally":
        return "candidate"
    return None  # reference problems, runner errors: never excusable


class Case:
    def __init__(self, suite, path):
        self.path = path
        rel = path.relative_to(suite)
        self.replay = path.name.endswith(".replay.json")
        stem = path.name[:-len(".replay.json")] if self.replay else path.stem
        self.id = str(rel.parent / stem)
        self.area = rel.parts[0] if len(rel.parts) > 1 else "."
        base = path.parent / stem
        self.stdin = base.with_name(stem + ".stdin")
        self.fixture = base.with_name(stem + ".fixture")
        status = base.with_name(stem + ".status")
        self.status = int(status.read_text().strip()) if status.exists() else 0
        args = base.with_name(stem + ".args")
        self.args = args.read_text().splitlines() if args.exists() else []
        timeout = base.with_name(stem + ".timeout")
        self.timeout = float(timeout.read_text().strip()) if timeout.exists() else None


def discover(suite):
    cases = []
    for path in sorted(suite.rglob("*")):
        if not path.is_file() or path.name == "known-differences.json":
            continue
        if any(part.endswith(".fixture") for part in path.relative_to(suite).parts[:-1]):
            continue
        if path.suffix == ".sh" or path.name.endswith(".replay.json"):
            cases.append(Case(suite, path))
        elif path.suffix not in SIDE_CARS:
            raise SystemExit(f"unrecognized file in suite: {path.relative_to(suite)}")
    ids = [c.id for c in cases]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise SystemExit(f"duplicate case ids: {sorted(duplicates)}")
    return cases


def load_known(path):
    if not path.exists():
        return {}
    known = json.loads(path.read_text())
    if not isinstance(known, dict):
        raise SystemExit(f"{path}: expected an object mapping case id to an entry")
    for case_id, entry in known.items():
        if case_id.startswith("_"):
            continue  # comments
        if not isinstance(entry, dict) or entry.get("category") not in CATEGORIES \
                or not str(entry.get("reason", "")).strip():
            raise SystemExit(f"{path}: {case_id}: needs a category from {sorted(CATEGORIES)} and a reason")
        unknown = set(entry.get("differences", [])) - ASPECTS
        if unknown:
            raise SystemExit(f"{path}: {case_id}: unknown differences {sorted(unknown)}")
    return {k: v for k, v in known.items() if not k.startswith("_")}


def select(cases, areas, patterns):
    chosen = []
    for case in cases:
        if areas and case.area not in areas:
            continue
        if patterns and not any(fnmatch.fnmatchcase(case.id, p) for p in patterns):
            continue
        chosen.append(case)
    return chosen


def text_diff(left, right, limit):
    a = left.decode(errors="backslashreplace").splitlines()
    b = right.decode(errors="backslashreplace").splitlines()
    lines = list(difflib.unified_diff(a, b, "reference", "candidate", n=1, lineterm=""))
    if not lines and left != right:
        lines = [f"(same lines; bytes differ: reference {len(left)} bytes, candidate {len(right)} bytes)"]
    if len(lines) > limit:
        lines = lines[:limit] + [f"... ({len(lines) - limit} more diff lines)"]
    return lines


def tree_diff(directory, limit):
    trees = []
    for side in ("reference", "candidate"):
        path = directory / side / "tree.json"
        trees.append(json.loads(path.read_text()) if path.exists() else {})
    lines = []
    for name in sorted(set(trees[0]) | set(trees[1])):
        a, b = trees[0].get(name), trees[1].get(name)
        if a != b:
            def show(item):
                if item is None:
                    return "absent"
                item = dict(item)
                if item.get("hardlink") == name:
                    del item["hardlink"]  # only a link to another path is informative
                if "mode" in item:
                    item["mode"] = oct(item["mode"])
                if "sha256" in item:
                    item["sha256"] = item["sha256"][:12]
                return json.dumps(item, sort_keys=True)
            lines.append(f"{name}: reference {show(a)} / candidate {show(b)}")
    if len(lines) > limit:
        lines = lines[:limit] + [f"... ({len(lines) - limit} more entries)"]
    return lines


def short_diff(directory, report, limit=40):
    """A compact human diff of a finished case."""
    lines = []
    outcomes = report.get("outcomes") or []
    differences = report.get("differences", [])
    if report.get("error"):
        lines.append("runner error: " + report["error"])
    if "exit status" in differences and len(outcomes) >= 2:
        lines.append(f"exit status: reference {outcomes[0]['exit_status']}, "
                     f"candidate {outcomes[1]['exit_status']}")
    for item in differences:
        if item.startswith(("reference exit", "reference did not", "candidate did not")):
            lines.append(item)
    for stream in ("stdout", "stderr", "terminal"):
        if any(d.startswith(stream + " bytes") for d in differences):
            left, right = [(directory / side / stream) for side in ("reference", "candidate")]
            if left.exists() and right.exists():
                lines.append(f"--- {stream}")
                lines += text_diff(left.read_bytes(), right.read_bytes(), limit)
    if any(d.startswith("filesystem") for d in differences):
        lines.append("--- filesystem")
        lines += tree_diff(directory, limit)
    return lines


class Driver:
    def __init__(self, args, images):
        self.args = args
        self.images = images
        self.processes = set()
        self.lock = threading.Lock()
        self.stopping = False

    def command(self, case, output):
        args = self.args
        mode = "replay" if case.replay else "run"
        command = [sys.executable, str(RUNNER), mode, "--workspace", str(args.workspace),
                   "--output", str(output), "--reference", self.images[0]["id"],
                   "--candidate", self.images[1]["id"],
                   "--timeout", str(case.timeout or args.timeout),
                   "--memory", args.memory, "--cpus", args.cpus]
        if case.replay:
            command += ["--events", str(case.path)]
        else:
            command += ["--script", str(case.path), "--expect-status", str(case.status)]
            if case.stdin.exists():
                command += ["--stdin", str(case.stdin)]
            command += ["--arg=" + arg for arg in case.args]
        if case.fixture.is_dir():
            command += ["--fixture", str(case.fixture)]
        return command

    def run(self, case, known):
        output = self.args.output / "cases" / case.id
        output.parent.mkdir(parents=True, exist_ok=True)
        command = self.command(case, output)
        started = time.monotonic()
        log = output.parent / (output.name + ".log")
        with log.open("wb") as handle:
            with self.lock:
                if self.stopping:
                    return {"id": case.id, "area": case.area, "result": "fail",
                            "runner_exit": None, "differences": ["not run: interrupted"],
                            "seconds": 0, "output": str(output)}
                process = subprocess.Popen(command, stdout=handle, stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL)
                self.processes.add(process)
            try:
                # The runner bounds every execution; this guards against a wedged Docker client.
                limit = (case.timeout or self.args.timeout) * 4 + 120
                code = process.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                process.terminate()
                code = process.wait(timeout=60)
            finally:
                with self.lock:
                    self.processes.discard(process)
        seconds = round(time.monotonic() - started, 2)
        report_path = output / "report.json"
        report = json.loads(report_path.read_text()) if report_path.exists() else \
            {"passed": False, "status": "error", "differences": [], "error": "no report.json"}
        differences = list(report.get("differences", []))
        if report.get("status") != "complete" and report.get("error"):
            differences.append("runner error: " + report["error"])
        entry = known.get(case.id)
        passed = code == 0 and report.get("passed") is True
        if entry is None:
            result = "pass" if passed else "fail"
        elif passed:
            result = "xpass"
        else:
            aspects = [aspect(d) for d in differences]
            allowed = set(entry.get("differences", ASPECTS))
            excusable = code == 1 and report.get("status") == "complete" and differences \
                and all(a is not None and a in allowed for a in aspects)
            result = "xfail" if excusable else "fail"
        record = {"id": case.id, "area": case.area, "result": result, "runner_exit": code,
                  "differences": differences, "seconds": seconds,
                  "output": str(output.relative_to(self.args.output))}
        if entry:
            record["known"] = entry
        if result != "pass":
            record["diff"] = short_diff(output, report)
        return record

    def terminate(self):
        with self.lock:
            self.stopping = True
            for process in self.processes:
                if process.poll() is None:
                    process.terminate()  # the runner removes its own containers on SIGTERM


def markdown(summary):
    lines = ["# Docker parity suite", "",
             f"- Started: {summary['started']}  ",
             f"- Duration: {summary['seconds']} s at --jobs {summary['jobs']}  ",
             f"- Reference: `{summary['images'][0]['requested']}` `{summary['images'][0]['id']}`  ",
             f"- Candidate: `{summary['images'][1]['requested']}` `{summary['images'][1]['id']}`  ",
             f"- Runner sha256: `{summary['runner_sha256']}`  ",
             f"- Verdict: **{'PASS' if summary['ok'] else 'FAIL'}**", "",
             "| Area | Cases | pass | xfail | fail | xpass |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for area, counts in summary["areas"].items():
        lines.append(f"| {area} | {sum(counts.values())} | " + " | ".join(str(counts[r]) for r in RESULTS) + " |")
    totals = summary["totals"]
    lines.append(f"| **total** | **{sum(totals.values())}** | " +
                 " | ".join(f"**{totals[r]}**" for r in RESULTS) + " |")
    lines.append("")
    if summary["stale_known"]:
        lines += ["## Known-difference entries without a case", ""]
        lines += [f"- `{k}`" for k in summary["stale_known"]] + [""]
    for title, result in (("Failures", "fail"), ("Unexpected passes (prune these known-difference entries)", "xpass"),
                          ("Known differences (xfail)", "xfail")):
        cases = [c for c in summary["cases"] if c["result"] == result]
        if not cases:
            continue
        lines += [f"## {title}", ""]
        for case in cases:
            lines.append(f"### `{case['id']}`")
            lines.append("")
            if case.get("known"):
                lines.append(f"Known ({case['known']['category']}): {case['known']['reason']}")
                lines.append("")
            lines.append("Differences: " + ("; ".join(case["differences"]) or "none"))
            lines.append("")
            if result != "xpass" and case.get("diff"):
                lines += ["```diff"] + case["diff"] + ["```", ""]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("patterns", nargs="*", help="case id globs, e.g. 'text/sort-*' (same as --case)")
    parser.add_argument("--workspace", type=Path, default=os.environ.get("PARITY_WORKSPACE"),
                        help="default $PARITY_WORKSPACE")
    parser.add_argument("--output", type=Path, help="new result directory; default WORKSPACE/suite-results/TIMESTAMP")
    parser.add_argument("--suite", type=Path, default=SUITE, help="case directory")
    parser.add_argument("--known", type=Path, help="known differences; default SUITE/known-differences.json")
    parser.add_argument("--area", action="append", default=[], help="run only this area (repeatable)")
    parser.add_argument("--case", action="append", default=[], help="case id glob (repeatable)")
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--reference", default="bash-os:parity-debian")
    parser.add_argument("--candidate", default="bash-os:parity-bash-os")
    parser.add_argument("--timeout", type=float, default=30, help="default seconds per execution")
    parser.add_argument("--memory", default="512m")
    parser.add_argument("--cpus", default="2")
    parser.add_argument("--list", action="store_true", help="list the selected cases and exit")
    parser.add_argument("--compare", type=Path, help="an earlier summary.json; report cases whose result changed")
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be at least 1")
    suite = args.suite.resolve()
    cases = discover(suite)
    known = load_known(args.known or suite / "known-differences.json")
    patterns = args.patterns + args.case
    selected = select(cases, set(args.area), patterns)
    if args.list:
        for case in selected:
            print(case.id + (f"  [known: {known[case.id]['category']}]" if case.id in known else ""))
        return 0
    if not selected:
        parser.error("no cases selected")
    if args.workspace is None:
        parser.error("--workspace or PARITY_WORKSPACE is required")
    runner = load_runner()
    try:
        args.workspace = runner.safe_path(args.workspace)
        if args.output:
            args.output = runner.safe_path(args.output)
    except argparse.ArgumentTypeError as error:
        parser.error(str(error))
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    args.output = args.output or args.workspace / "suite-results" / stamp
    args.output.mkdir(parents=True, exist_ok=False)
    images = [runner.image_info(args.reference), runner.image_info(args.candidate)]
    for side, image in zip(("reference", "candidate"), images):
        print(f"{side}: {image['requested']} = {image['id']}", flush=True)
    print(f"Results: {args.output}", flush=True)
    # Entries for cases that no longer exist are stale; only a full run can tell.
    stale = sorted(set(known) - {c.id for c in cases}) if not (args.area or patterns) else []
    driver = Driver(args, images)

    def stop(_signal, _frame):
        driver.terminate()
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    started = datetime.datetime.now(datetime.timezone.utc)
    clock = time.monotonic()
    records = []
    interrupted = False
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs)
    try:
        futures = {pool.submit(driver.run, case, known): case for case in selected}
        for future in concurrent.futures.as_completed(futures):
            record = future.result()
            records.append(record)
            mark = record["result"].upper()
            print(f"{mark:5} {record['id']} ({record['seconds']} s)", flush=True)
    except KeyboardInterrupt:
        interrupted = True
        driver.terminate()
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
    records.sort(key=lambda r: r["id"])
    areas = {}
    for record in records:
        areas.setdefault(record["area"], {r: 0 for r in RESULTS})[record["result"]] += 1
    totals = {r: sum(a[r] for a in areas.values()) for r in RESULTS}
    ok = not interrupted and not stale and len(records) == len(selected) \
        and totals["fail"] == 0 and totals["xpass"] == 0
    summary = {"started": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
               "seconds": round(time.monotonic() - clock, 1), "jobs": args.jobs,
               "images": [{"requested": i["requested"], "id": i["id"],
                           "repo_digests": i["repo_digests"]} for i in images],
               "runner_sha256": hashlib.sha256(RUNNER.read_bytes()).hexdigest(),
               "suite": str(suite), "selection": {"areas": args.area, "patterns": patterns},
               "interrupted": interrupted, "stale_known": stale, "ok": ok,
               "areas": dict(sorted(areas.items())), "totals": totals, "cases": records}
    if args.compare:
        before = {c["id"]: c["result"] for c in json.loads(args.compare.read_text())["cases"]}
        summary["changed"] = [{"id": r["id"], "before": before[r["id"]], "after": r["result"]}
                              for r in records if r["id"] in before and before[r["id"]] != r["result"]]
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (args.output / "summary.md").write_text(markdown(summary))
    print("", flush=True)
    for area, counts in summary["areas"].items():
        print(f"{area:12} " + " ".join(f"{r}={counts[r]}" for r in RESULTS))
    print(f"{'total':12} " + " ".join(f"{r}={totals[r]}" for r in RESULTS) +
          f"  ({summary['seconds']} s, --jobs {args.jobs})")
    for record in records:
        if record["result"] in ("fail", "xpass"):
            note = "prune known-differences entry" if record["result"] == "xpass" else "; ".join(record["differences"])
            print(f"{record['result'].upper()}: {record['id']}: {note}")
    for case_id in stale:
        print(f"STALE: known-differences entry {case_id} has no case")
    if args.compare:
        for change in summary["changed"]:
            print(f"CHANGED: {change['id']}: {change['before']} -> {change['after']}")
    for side, image in zip(("reference", "candidate"), images):
        print(f"{side} image id: {image['id']}")
    print(("PASS" if ok else "FAIL") + f": {args.output / 'summary.md'}", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
