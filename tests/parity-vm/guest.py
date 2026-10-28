#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""VM-only evaluator for terminal, network, shell and normative-data checks."""
import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

import network
import terminal
import schema

ROOT = Path("/opt/bashos-parity")
REFERENCE_SHELL = Path("/opt/bash-5.3.15/bin/bash")
SCRATCH = (("/tmp", "128M", "1777"), ("/var/tmp", "64M", "1777"),
           ("/dev/shm", "64M", "1777"), ("/home/parity", "16M", "0755"))
scratch_mounted = False
# Set by --allow-root-fixtures; the controller passes it only for rental runs.
allow_root = False
LOOP_CLR_FD = 0x4C01


def require_guest(token):
    uuid.UUID(token)
    marker = Path("/etc/bashos-parity-vm")
    if not marker.is_file() or marker.read_text().strip() != token:
        raise RuntimeError("refusing execution outside the disposable parity VM")
    if Path("/sys/class/dmi/id/product_uuid").read_text().strip().lower() != token.lower():
        raise RuntimeError("VM identity mismatch")
    virt = subprocess.check_output(["systemd-detect-virt", "--vm"], text=True).strip()
    if virt not in ("kvm", "qemu") or os.geteuid() != 0:
        raise RuntimeError("expected a QEMU guest controller")
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    if [link["ifname"] for link in links] != ["lo"]:
        raise RuntimeError("fixture network must be a fresh loopback-only namespace")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    return {"virtualization": virt, "uid": os.geteuid(), "links": [link["ifname"] for link in links],
            "vm_uuid_matches": True, "pid_namespace": os.readlink("/proc/self/ns/pid"),
            "network_namespace": os.readlink("/proc/self/ns/net"),
            "mount_namespace": os.readlink("/proc/self/ns/mnt")}


def b64(data):
    return base64.b64encode(data).decode()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True) + "\n")


def environment(mode):
    return {"LC_ALL": "C.UTF-8", "LANG": "C.UTF-8", "TZ": "UTC", "TERM": "xterm-256color",
            "HOME": "/tmp/parity-home", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin" if mode == "reference" else "/empty",
            "BASH_ENV": "", "ENV": "", "INPUTRC": "/dev/null", "HISTFILE": "/dev/null",
            "PS1": "PARITY> ", "PS2": "MORE> ", "PROMPT_COMMAND": ""}


def workspace(case):
    global scratch_mounted
    # The evaluator already has a private mount namespace. Replace every
    # general-purpose writable location between sides, not just the test cwd.
    for name, size, mode in SCRATCH:
        if scratch_mounted:
            subprocess.run(["umount", name], check=True, capture_output=True)
        subprocess.run(["mount", "-t", "tmpfs", "-o", "nodev,nosuid,size=" + size + ",mode=" + mode,
                        "parity-scratch", name], check=True, capture_output=True)
    scratch_mounted = True
    root = Path("/tmp/parity-case")
    for folder in (root, Path("/tmp/parity-home")):
        if folder.exists():
            shutil.rmtree(folder)
        folder.mkdir(mode=0o755)
        os.chown(folder, 2000, 2000)
    for name, text in case.get("files", {}).items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe fixture path")
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        data = base64.b64decode(text["base64"], validate=True) if isinstance(text, dict) else text.encode()
        path.write_bytes(data)
        os.chown(path, 2000, 2000)
        for parent in path.parents:
            if parent == root:
                break
            os.chown(parent, 2000, 2000)
    return root


def diagnostics(case, root=Path("/tmp/parity-home")):
    """Retain requested HOME logs as evidence, separately from compared files."""
    records = {}
    remaining = 4 * 1024**2
    for name in case.get("diagnostic_files", []):
        path = root
        try:
            parts = Path(name).parts
            info = root.lstat()
            if not stat.S_ISDIR(info.st_mode):
                records[name] = {"error": "diagnostic root is not a directory"}
                continue
            for index, part in enumerate(parts):
                path = path / part
                info = path.lstat()
                if stat.S_ISLNK(info.st_mode):
                    raise ValueError("diagnostic symlink refused")
                if index < len(parts) - 1 and not stat.S_ISDIR(info.st_mode):
                    raise ValueError("diagnostic parent is not a directory")
            if not stat.S_ISREG(info.st_mode):
                records[name] = {"error": "diagnostic is not a regular file"}
                continue
            limit = min(1024**2, remaining)
            with path.open("rb") as handle:
                data = handle.read(limit + 1)
            truncated = len(data) > limit
            data = data[:limit]
            remaining -= len(data)
            records[name] = {"base64": b64(data), "captured_bytes": len(data),
                             "truncated": truncated}
        except FileNotFoundError:
            records[name] = {"missing": True}
        except (OSError, ValueError) as exc:
            records[name] = {"error": str(exc)}
    return records


def tree(root):
    result = {}
    size = 0
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        record = {"mode": stat.S_IMODE(info.st_mode)}
        if stat.S_ISLNK(info.st_mode):
            record.update(kind="symlink", target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            record.update(kind="directory")
        elif stat.S_ISREG(info.st_mode):
            size += info.st_size
            if size > 16 * 1024**2:
                raise RuntimeError("fixture file-size limit")
            record.update(kind="file", base64=b64(path.read_bytes()))
        elif stat.S_ISFIFO(info.st_mode):
            record.update(kind="fifo")
        elif stat.S_ISSOCK(info.st_mode):
            record.update(kind="socket")
        elif stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
            # Metadata only: never open a device while collecting evidence.
            record.update(kind="character-device" if stat.S_ISCHR(info.st_mode) else "block-device",
                          major=os.major(info.st_rdev), minor=os.minor(info.st_rdev))
        else:
            raise RuntimeError("unexpected filesystem object")
        result[str(path.relative_to(root))] = record
        if len(result) > 2048:
            raise RuntimeError("fixture file-count limit")
    return result


def plain(argv, env, root, case):
    terminal.set_subreaper()
    file_size_limit = schema.file_size_limit(case)
    proc = subprocess.Popen(argv, cwd=root, env=env, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True,
                            preexec_fn=lambda: terminal.child_limits(file_size_limit,
                                                                     case.get("privilege") == "root"))
    error = None
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    total = 0
    limit = case.get("output_limit", 8 * 1024**2)
    deadline = time.monotonic() + case.get("timeout", 12)
    pending = memoryview(case.get("stdin", "").encode())
    try:
        with selectors.DefaultSelector() as selector:
            for stream, label in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            if pending:
                os.set_blocking(proc.stdin.fileno(), False)
                selector.register(proc.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                proc.stdin.close()
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    error = "wall-clock limit"
                    break
                for key, _ in selector.select(min(.1, remaining)):
                    if key.data == "stdin":
                        try:
                            n = os.write(key.fd, pending[:65536])
                            pending = pending[n:]
                        except BrokenPipeError:
                            pending = pending[:0]
                        if not pending:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                        continue
                    data = os.read(key.fd, 65536)
                    if not data:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    keep = min(len(data), max(0, limit - total))
                    captured[key.data].extend(data[:keep])
                    total += len(data)
                    if total > limit:
                        error = "output limit"
                        break
                if error:
                    break
        if error is None:
            try:
                proc.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                error = "wall-clock limit"
    finally:
        strays = [p for p in terminal.owned_processes(proc.pid) if p["state"] != "Z"]
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            stream.close()
        later = terminal.cleanup(proc.pid)
        strays.extend(p for p in later if p["pid"] not in {s["pid"] for s in strays})
    if strays and error is None:
        error = "fixture left live child processes"
    return {"status": proc.returncode, "stdout_base64": b64(captured["stdout"]),
            "stderr_base64": b64(captured["stderr"]), "error": error,
            "captured_bytes": sum(map(len, captured.values())), "stray_processes": strays,
            "configured_file_size_limit": file_size_limit}


def kernel_state():
    """Global kernel objects a privileged fixture can leave behind, plus the clock offset."""
    loops = {}
    for path in Path("/sys/block").glob("loop*/loop/backing_file"):
        loops["/dev/" + path.parent.parent.name] = path.read_text().strip()
    swaps = Path("/proc/swaps").read_text().splitlines()[1:]
    return {"loop": loops, "device_mapper": sorted(p.name for p in Path("/sys/block").glob("dm-*")),
            "swap": sorted(line.split()[0] for line in swaps if line.split()),
            "modules": sorted(line.split()[0] for line in Path("/proc/modules").read_text().splitlines()),
            "clock_offset": time.clock_gettime(time.CLOCK_REALTIME) - time.clock_gettime(time.CLOCK_BOOTTIME)}


def leftovers(before, after):
    found = {"swap": sorted(set(after["swap"]) - set(before["swap"])),
             "device_mapper": sorted(set(after["device_mapper"]) - set(before["device_mapper"])),
             "loop": sorted(set(after["loop"]) - set(before["loop"]))}
    if abs(after["clock_offset"] - before["clock_offset"]) > 1:
        found["realtime_clock"] = ["moved %.3f s" % (after["clock_offset"] - before["clock_offset"])]
    return {name: items for name, items in found.items() if items}


def clean_kernel_state(before):
    """Undo a privileged side's swap, device-mapper, loop and clock changes, newest layer first."""
    found = leftovers(before, kernel_state())
    tools = environment("reference")["PATH"]
    # Release this namespace's mounts of block devices first, deepest first.
    for line in reversed(Path("/proc/self/mountinfo").read_text().splitlines()):
        fields = line.split()
        source = fields[fields.index("-") + 2]
        if source.startswith(("/dev/loop", "/dev/mapper/", "/dev/dm-")):
            subprocess.run(["umount", "-l", fields[4]], capture_output=True, timeout=10)
    for name in found.get("swap", []):
        subprocess.run([shutil.which("swapoff", path=tools) or "swapoff", name], capture_output=True, timeout=10)
    if found.get("device_mapper") and shutil.which("dmsetup", path=tools):
        subprocess.run([shutil.which("dmsetup", path=tools), "remove_all", "--force"], capture_output=True, timeout=10)
    for name in found.get("loop", []):
        try:
            fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC)
            try:
                fcntl.ioctl(fd, LOOP_CLR_FD)
            finally:
                os.close(fd)
        except OSError:
            pass
    if "realtime_clock" in found:
        time.clock_settime(time.CLOCK_REALTIME, time.clock_gettime(time.CLOCK_BOOTTIME) + before["clock_offset"])
    return found


def privileged(run):
    """Run one side of a root fixture as uid 0 in fresh mount, network, UTS and IPC namespaces.

    Kernel objects outside those namespaces (loop, device-mapper, swap, the realtime
    clock) are restored afterwards; anything still present makes the side ERROR."""
    read, write = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        os.close(read)
        code = 0
        try:
            os.unshare(os.CLONE_NEWNS | os.CLONE_NEWNET | os.CLONE_NEWUTS | os.CLONE_NEWIPC)
            subprocess.run(["mount", "--make-rprivate", "/"], check=True, capture_output=True)
            subprocess.run(["ip", "link", "set", "lo", "up"], check=True, capture_output=True)
            before = kernel_state()
            try:
                result = run()
            finally:
                cleaned = clean_kernel_state(before)
            result["root_isolation"] = {"before": before, "cleaned": cleaned,
                                        "namespaces": {n: os.readlink("/proc/self/ns/" + n)
                                                       for n in ("mnt", "net", "uts", "ipc")}}
        except BaseException as exc:
            message = "privileged side failed: " + str(exc)
            result = {"status": None, "stdout_base64": "", "stderr_base64": "", "screen_base64": "",
                      "error": message, "harness_error": message, "tree": {}, "captured_bytes": 0,
                      "stray_processes": []}
            code = 2
        with os.fdopen(write, "wb") as stream:
            stream.write(json.dumps(result).encode())
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)
    os.close(write)
    with os.fdopen(read, "rb") as stream:
        data = stream.read()
    os.waitpid(pid, 0)
    terminal.cleanup(-1)
    result = json.loads(data)
    isolation = result.get("root_isolation")
    if isolation:
        # The side's mount namespace is released asynchronously after its last process exits.
        for _ in range(50):
            remaining = leftovers(isolation["before"], kernel_state())
            if not remaining:
                break
            time.sleep(.1)
        isolation["remaining"] = remaining
        if remaining and not result.get("harness_error"):
            result["harness_error"] = "privileged fixture left kernel state: " + json.dumps(remaining)
    return result


def side(case, mode):
    if case.get("privilege") == "root":
        return privileged(lambda: unprivileged_side(case, mode))
    return unprivileged_side(case, mode)


def unprivileged_side(case, mode):
    root = workspace(case)
    setup = None
    if case.get("setup_script"):
        setup = plain([str(REFERENCE_SHELL), "--noprofile", "--norc", "-c",
                       "set -e; set -o pipefail\n" + case["setup_script"]],
                      environment("reference"), root,
                      {"timeout": case.get("setup_timeout", 30),
                       "file_size_limit": schema.file_size_limit(case),
                       "privilege": case.get("privilege")})
        if setup["status"] != 0 or setup.get("error"):
            return {**setup, "tree": tree(root), "screen_base64": "", "setup": setup,
                    "diagnostics": diagnostics(case),
                    "harness_error": "fixture setup failed before behavioral execution"}
    env = environment(mode)
    shell = str(REFERENCE_SHELL) if mode == "reference" else str(ROOT / "candidate")
    script = case.get(mode + "_script", case.get("script"))
    argv = [shell, "--noprofile", "--norc"]
    argv += ["-i"] if case.get("interactive_shell") else ["-c", script]
    if case["driver"] == "pty":
        result = terminal.execute(argv, env, root, case)
    elif case["driver"] == "network":
        with network.peer(case["peer"], case) as (port, requests, errors):
            env["FIXTURE_PORT"] = str(port)
            result = plain(argv, env, root, case)
        result["requests"] = requests
        result["peer_errors"] = errors
        if requests.setup:
            result["peer_setup"] = requests.setup
    else:
        result = plain(argv, env, root, case)
    result["tree"] = tree(root)
    if case.get("diagnostic_files"):
        result["diagnostics"] = diagnostics(case)
    if setup is not None:
        result["setup"] = setup
    return result


def expectations(case, result):
    problems = []
    if result["error"]:
        problems.append(result["error"])
    if result["status"] != case.get("expected_status", 0):
        problems.append("exit status")
    for field in ("stdout", "stderr"):
        if field in case and result.get(field + "_base64") != b64(case[field].encode()):
            problems.append("expected " + field)
        if field + "_base64" in case and result.get(field + "_base64") != case[field + "_base64"]:
            problems.append("expected " + field)
    if case.get("restore_terminal", True) and result.get("terminal_restored") is False:
        problems.append("terminal modes were not restored")
    for name, data in case.get("expected_files", {}).items():
        expected = data["base64"] if isinstance(data, dict) else b64(data.encode())
        if result["tree"].get(name, {}).get("base64") != expected:
            problems.append("expected file: " + name)
    if result.get("peer_errors"):
        problems.extend("peer: " + error for error in result["peer_errors"])
    for index, expected in enumerate(case.get("expected_requests", [])):
        if index >= len(result.get("requests", [])):
            problems.append("missing request " + str(index))
            continue
        actual = result["requests"][index]
        for key, value in expected.items():
            if actual.get(key) != value:
                problems.append("request " + str(index) + " " + key)
    if "expected_requests" in case and len(result.get("requests", [])) != len(case["expected_requests"]):
        problems.append("request count")
    return problems


def evaluate(case, output):
    output.mkdir()
    metadata = {"id": case["id"], "loadable": case["loadable"], "group": case["group"],
                "kind": case.get("kind", "parity"), "covers": case.get("covers", [])}
    if case.get("optional"):
        available = plain([str(ROOT / "candidate"), "--noprofile", "--norc", "-c",
                           'builtin type -t -- "$1"', "availability", case["loadable"]],
                          environment("candidate"), workspace({}), {"timeout": 3})
        write_json(output / "availability.json", available)
        if available.get("error"):
            return {**metadata, "status": "ERROR", "reason": "optional availability probe failed"}
        if available["status"] != 0 or available["stdout_base64"] != b64(b"builtin\n"):
            return {**metadata, "status": "SKIP", "reason": "optional loadable is absent from this build"}
    if case.get("privilege") == "root" and not allow_root:
        return {**metadata, "status": "ERROR",
                "reason": "root fixture selected without --allow-root-fixtures (rental runs only)"}
    missing = [name for name in case.get("requires", [])
               if not shutil.which(name, path=environment("reference")["PATH"])]
    if missing:
        return {**metadata, "status": "ERROR", "reason": "missing fixture dependencies",
                "missing_dependencies": missing}
    feature_checks = {}
    if "userns" in case.get("features", []):
        tool = shutil.which("unshare", path=environment("reference")["PATH"])
        if not tool:
            return {**metadata, "status": "ERROR", "reason": "userns preflight requires unshare"}
        probe = plain([tool, "--user", "--map-root-user", "--mount", "--net", "--pid", "--fork",
                       "/usr/bin/true"], environment("reference"), workspace({}), {"timeout": 5})
        feature_checks["userns"] = probe
        if probe.get("error"):
            write_json(output / "feature-checks.json", feature_checks)
            return {**metadata, "status": "ERROR", "reason": "userns preflight failed to complete"}
        if probe["status"] != 0:
            write_json(output / "feature-checks.json", feature_checks)
            diagnostic = base64.b64decode(probe["stderr_base64"])
            unavailable = probe["status"] == 1 and any(text in diagnostic for text in
                (b"Operation not permitted", b"Permission denied", b"not supported", b"Function not implemented"))
            return {**metadata, "status": "SKIP" if unavailable else "ERROR",
                    "reason": "guest policy does not allow unprivileged user/mount/network/PID namespaces"
                              if unavailable else "unexpected failure of userns preflight"}
    if "seccomp-notify" in case.get("features", []):
        available = Path("/proc/sys/kernel/seccomp/actions_avail")
        actions = available.read_text().split() if available.is_file() else []
        feature_checks["seccomp-notify"] = {"actions_avail": actions}
        if "user_notif" not in actions:
            write_json(output / "feature-checks.json", feature_checks)
            return {**metadata, "status": "SKIP", "reason": "guest kernel lacks seccomp user notification"}
    if feature_checks:
        write_json(output / "feature-checks.json", feature_checks)
    if case.get("kind") == "contract":
        candidate = side(case, "candidate")
        write_json(output / "candidate.json", candidate)
        differences = expectations(case, candidate)
        return {"id": case["id"], "loadable": case["loadable"], "group": case["group"], "kind": "contract",
                "status": "ERROR" if candidate.get("harness_error") else "FAIL" if differences else "PASS",
                "harness_error": candidate.get("harness_error"), "differences": differences,
                "covers": case.get("covers", []), "oracle": case["oracle"],
                "comparison": case.get("comparison", "independent contract; no GNU reference executable")}
    reference = side(case, "reference")
    write_json(output / "reference.json", reference)
    invalid = expectations(case, reference)
    # Still run the candidate for diagnostic evidence; an invalid oracle is ERROR.
    candidate = side(case, "candidate")
    write_json(output / "candidate.json", candidate)
    differences = expectations(case, candidate)
    harness_errors = {label: result["harness_error"] for label, result in
                      (("reference", reference), ("candidate", candidate)) if result.get("harness_error")}
    fields = ["status", "tree"]
    if case["driver"] == "pty":
        if case.get("compare_screen", False):
            fields.append("screen_base64")
    else:
        fields += ["stdout_base64", "stderr_base64"]
    for field in fields:
        if candidate[field] != reference[field]:
            differences.append("reference " + field)
    for key in case.get("compare_request_keys", []):
        if [r.get(key) for r in candidate.get("requests", [])] != [r.get(key) for r in reference.get("requests", [])]:
            differences.append("reference requests:" + key)
    return {"id": case["id"], "loadable": case["loadable"], "group": case["group"],
            "kind": "parity",
            "oracle": case.get("oracle"),
            "status": "ERROR" if invalid or harness_errors else "FAIL" if differences else "PASS",
            "harness_errors": harness_errors,
            "reference_problems": invalid, "differences": differences,
            "covers": case.get("covers", []),
            "comparison": case.get("comparison", "terminal semantics and file effects"
                                   if case["driver"] == "pty" and not case.get("compare_screen")
                                   else "exact bytes, status and file effects")}


def legacy_cases(directory):
    """Run historical fixtures and preserve their deferred/migration metadata."""
    path = ROOT / "loadable-parity" / "runner.py"
    spec = importlib.util.spec_from_file_location("legacy_runner", path)
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    terminal.set_subreaper()
    original_execute = runner.execute
    cleanup = {"executions": 0, "adopted_zombies_reaped": 0, "live_children_cleaned": 0}

    def execute_and_reap(*args, **kwargs):
        try:
            return original_execute(*args, **kwargs)
        finally:
            # Here Python is the namespace's PID 1. Reap bubblewrap's orphaned
            # helpers between cases, rather than accumulating zombies against
            # the evaluation cgroup's task limit. All test execution is serial.
            pending = terminal.owned_processes(-1)
            cleanup["executions"] += 1
            cleanup["adopted_zombies_reaped"] += sum(p["state"] == "Z" for p in pending)
            cleanup["live_children_cleaned"] += len(terminal.cleanup(-1))

    runner.execute = execute_and_reap
    records = []
    for path in sorted((ROOT / "loadable-parity" / "suites").glob("*.json")):
        suite = None
        try:
            suite = runner.validate(json.loads(path.read_text()))
            report = runner.run_suite(suite, ROOT / "candidate", directory / suite["loadable"])
            write_json(directory / suite["loadable"] / "fixture.json",
                       {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
            added = [{**case, "id": "legacy/" + suite["loadable"] + "/" + case["id"],
                      "loadable": suite["loadable"], "group": "legacy"} for case in report["cases"]]
        except Exception as exc:
            added = [{"id": "legacy/" + suite["loadable"] + "/" + case["id"], "group": "legacy",
                            "loadable": suite["loadable"], "kind": case["kind"],
                            **unexecuted_legacy(case, str(exc))}
                     for case in suite["cases"]] if suite else [
                         {"id": "legacy/" + path.stem + "/invalid-suite", "group": "legacy",
                          "kind": "infrastructure", "status": "ERROR", "reason": str(exc)}]
        records.extend(added)
        # Preserve completed suites even if a later evaluator failure interrupts
        # the child. The parent reads this journal after the child is reaped.
        with (directory / "records.jsonl").open("a") as journal:
            for record in added:
                journal.write(json.dumps(record) + "\n")
    write_json(directory / "cleanup.json", cleanup)
    return records


def unexecuted_legacy(case, reason):
    if case["kind"] == "deferred":
        return {"status": "DEFERRED", "reason": case["reason"]}
    if case["kind"] == "migrated":
        return {"status": "MIGRATED", "replacement_cases": case["replacement_cases"],
                "reason": "Scenario moved to named fixtures; this marker is not an execution result."}
    return {"status": "ERROR", "reason": reason}


def backfill_legacy(records, suites, reason):
    """Keep every known case visible even if the worker never starts."""
    seen = {r["id"] for r in records}
    expected = backfilled = invalid = 0
    for path in sorted(suites.glob("*.json")):
        try:
            suite = json.loads(path.read_text())
            pending = []
            for case in suite["cases"]:
                name = "legacy/" + suite["loadable"] + "/" + case["id"]
                expected += 1
                if name not in seen:
                    pending.append({"id": name, "group": "legacy", "loadable": suite["loadable"],
                                    "kind": case["kind"],
                                    **unexecuted_legacy(case, reason)})
            records.extend(pending)
            backfilled += len(pending)
        except Exception as exc:
            invalid += 1
            name = "legacy/" + path.stem + "/invalid-suite"
            if name not in seen:
                records.append({"id": name, "group": "legacy", "kind": "infrastructure",
                                "status": "ERROR", "reason": str(exc)})
    return {"expected_cases": expected, "backfilled_cases": backfilled, "invalid_suite_files": invalid}


def legacy(output):
    """Run the historical namespace runner as uid/gid 2000 inside this VM."""
    workspace({})
    directory = output / "legacy"
    directory.mkdir()
    os.chown(directory, 2000, 2000)
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            # Historical logname cases require a synthetic login identity.
            # id -Gn deliberately exercises a supplementary group omitted
            # from the runner's one-entry group database. Set both conditions
            # explicitly instead of inheriting a workstation login/session.
            Path("/proc/self/loginuid").write_text("2000")
            os.setgroups([2001])
            os.setgid(2000)
            os.setuid(2000)
            write_json(directory / "identity.json", {"uid": os.getuid(), "euid": os.geteuid(),
                                                     "gid": os.getgid(), "groups": os.getgroups(),
                                                     "audit_login_uid": Path("/proc/self/loginuid").read_text().strip(),
                                                     "unmapped_supplementary_group": 2001})
            legacy_cases(directory)
        except BaseException as exc:
            write_json(directory / "infrastructure-error.json", {"error": str(exc)})
            code = 2
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(code)
    _, status = os.waitpid(pid, 0)
    terminal.cleanup(-1)
    # Preserve fixture modes/data while denying later uid-2000 groups any path
    # into the finished evidence. No legacy process or open descriptor remains.
    os.chown(directory, 0, 0)
    os.chmod(directory, 0o700)
    journal = directory / "records.jsonl"
    records = []
    failure = None
    if journal.exists():
        for line in journal.read_text().splitlines():
            try:
                records.append(json.loads(line))
            except ValueError as exc:
                failure = "invalid legacy journal: " + str(exc)
    error = directory / "infrastructure-error.json"
    if status:
        failure = error.read_text() if error.exists() else "legacy child status " + str(os.waitstatus_to_exitcode(status))
    identity = directory / "identity.json"
    if not identity.exists() or json.loads(identity.read_text()).get("euid") != 2000:
        failure = (failure + "; " if failure else "") + "legacy uid-2000 identity was not observed"
    accounting = backfill_legacy(records, ROOT / "loadable-parity/suites",
                                 failure or "legacy child omitted this case")
    write_json(directory / "accounting.json", accounting)
    if failure:
        records.append({"id": "legacy-infrastructure", "group": "legacy", "kind": "infrastructure",
                        "status": "ERROR", "reason": failure})
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm-token", required=True)
    parser.add_argument("--groups", required=True)
    parser.add_argument("--case-ids", help="comma-separated modern fixture IDs; selected groups still apply")
    parser.add_argument("--allow-root-fixtures", action="store_true",
                        help="run privilege=root fixtures (and their selfcheck) as uid 0")
    args = parser.parse_args()
    global allow_root
    allow_root = args.allow_root_fixtures
    isolation = require_guest(args.vm_token)
    output = ROOT / "results"
    output.mkdir(exist_ok=False)
    groups = set(args.groups.split(","))
    if not groups or groups - schema.GROUPS:
        parser.error("unknown or empty groups: " + ",".join(sorted(groups - schema.GROUPS)))
    records = []
    cases, fixture_hashes = schema.load(Path(__file__).parent / "suites")
    selected_ids = set(args.case_ids.split(",")) if args.case_ids is not None else None
    for case in schema.select(cases, groups, selected_ids):
        try:
            record = evaluate(case, output / case["id"])
        except Exception as exc:
            record = {"id": case["id"], "group": case["group"], "kind": case.get("kind", "parity"),
                      "status": "ERROR", "reason": str(exc)}
        records.append(record)
        print(json.dumps(record), flush=True)
    for group in sorted(groups & {"reference", "legacy", "selfcheck", "inventory"}):
        try:
            if group == "reference":
                from references import evaluate as evaluate_references
                extra = evaluate_references(ROOT, output)
            elif group == "legacy":
                extra = legacy(output)
            elif group == "inventory":
                from inventory import evaluate as evaluate_inventory
                extra = evaluate_inventory(ROOT, output)
            else:
                from selfcheck import evaluate as evaluate_selfcheck
                extra = evaluate_selfcheck(ROOT, output)
            if not extra:
                raise ValueError("selected group produced no records")
            records.extend(extra)
        except Exception as exc:
            if group == "legacy":
                backfill_legacy(records, ROOT / "loadable-parity/suites", str(exc))
            records.append({"id": group + "-infrastructure", "group": group, "kind": "infrastructure",
                            "status": "ERROR", "reason": str(exc)})
    for record in records:
        record.setdefault("kind", {"reference": "normative", "selfcheck": "selfcheck",
                                   "inventory": "metadata"}.get(record["group"], "infrastructure"))
    counts = {status: sum(r["status"] == status for r in records)
              for status in ("PASS", "FAIL", "ERROR", "SKIP", "DEFERRED", "MIGRATED", "COLLECTED")}
    report = {"schema": 1, "binary_sha256": hashlib.sha256((ROOT / "candidate").read_bytes()).hexdigest(),
              "fixture_sha256": fixture_hashes, "summary": counts, "cases": records,
              "groups": sorted(groups), "selected_case_ids": sorted(selected_ids) if selected_ids is not None else None,
              "vm_uuid": args.vm_token,
              "root_fixtures_allowed": allow_root,
              "isolation": isolation,
              "summary_by_group": {g: {s: sum(r["status"] == s and r["group"] == g for r in records)
                                       for s in counts} for g in sorted(groups)},
              "summary_by_kind": {k: {s: sum(r["status"] == s and r["kind"] == k for r in records)
                                      for s in counts} for k in sorted({r["kind"] for r in records})},
              "parity_summary_by_group": {g: {s: sum(r["status"] == s and r["kind"] == "parity"
                                                     and r["group"] == g for r in records) for s in counts}
                                          for g in sorted({r["group"] for r in records if r["kind"] == "parity"})},
              "scratch_mounts_reset_between_sides": [p[0] for p in SCRATCH],
              "legacy_identity": json.loads((output / "legacy/identity.json").read_text())
                  if (output / "legacy/identity.json").exists() else None,
              "legacy_accounting": json.loads((output / "legacy/accounting.json").read_text())
                  if (output / "legacy/accounting.json").exists() else None,
              "reference_shell": subprocess.check_output([str(REFERENCE_SHELL), "--version"], text=True).splitlines()[0],
              "reference_shell_sha256": hashlib.sha256(REFERENCE_SHELL.read_bytes()).hexdigest(),
              "legacy_reference_shell": subprocess.check_output(["/bin/bash", "--version"], text=True).splitlines()[0]}
    write_json(output / "summary.json", report)
    print(json.dumps(counts), flush=True)
    return int(bool(counts["FAIL"] or counts["ERROR"]))


if __name__ == "__main__":
    # Group evaluators import guest; share mount/cleanup state with this entrypoint.
    sys.modules["guest"] = sys.modules[__name__]
    raise SystemExit(main())
