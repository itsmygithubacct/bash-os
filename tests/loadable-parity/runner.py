#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run declarative loadable fixtures in mandatory, disposable Linux namespaces.

Each side gets a private filesystem, PID/network namespaces, no capabilities,
bounded resources, and no host home, devices, sockets or writable system paths.
There is deliberately no option to execute fixtures without this isolation.
"""
import argparse
import base64
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import tempfile
import time


NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}\Z")


def syscall_filter():
    """Deny global kernel operations, including keyrings shared across namespaces."""
    lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    ctx = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not ctx:
        raise RuntimeError("cannot create mandatory syscall filter")
    output = tempfile.TemporaryFile()
    try:
        for name in ("reboot", "init_module", "finit_module", "delete_module",
                     "kexec_load", "kexec_file_load", "swapon", "swapoff",
                     "keyctl", "add_key", "request_key", "bpf", "perf_event_open",
                     "userfaultfd", "ptrace", "process_vm_writev", "process_madvise",
                     "settimeofday", "clock_settime", "clock_adjtime", "adjtimex",
                     "iopl", "ioperm", "open_by_handle_at"):
            number = lib.seccomp_syscall_resolve_name(name.encode())
            if number >= 0 and lib.seccomp_rule_add(ctx, 0x50000 | errno.EPERM, number, 0) != 0:
                raise RuntimeError("cannot deny syscall: " + name)
        if lib.seccomp_export_bpf(ctx, output.fileno()) != 0:
            raise RuntimeError("cannot export mandatory syscall filter")
        output.seek(0)
        return output
    except BaseException:
        output.close()
        raise
    finally:
        lib.seccomp_release(ctx)


def validate(suite):
    if suite.get("version") != 1 or not NAME.fullmatch(suite.get("loadable", "")):
        raise ValueError("invalid suite version or loadable")
    if not isinstance(suite.get("cases"), list) or not suite["cases"]:
        raise ValueError("a suite needs cases")
    seen = set()
    for case in suite["cases"]:
        name = case.get("id", "")
        if not NAME.fullmatch(name) or name in seen:
            raise ValueError(f"invalid or duplicate case id: {name}")
        seen.add(name)
        kind = case.get("kind")
        if kind not in ("parity", "contract", "deferred"):
            raise ValueError(f"{name}: invalid kind")
        if not case.get("purpose"):
            raise ValueError(f"{name}: explain the behavior being tested")
        if kind == "deferred":
            if not case.get("reason"):
                raise ValueError(f"{name}: deferred case needs a reason")
            continue
        if not isinstance(case.get("script"), str) or not case["script"].strip():
            raise ValueError(f"{name}: missing script")
        if not isinstance(case.get("expected_status"), int) or not 0 <= case["expected_status"] <= 255:
            raise ValueError(f"{name}: expected_status must be explicit")
        if case.get("stderr") not in ("empty", "nonempty", "exact"):
            raise ValueError(f"{name}: invalid stderr policy")
        if not 0 < case.get("timeout", 5) <= 15:
            raise ValueError(f"{name}: timeout must be at most 15 seconds")
        if kind == "contract" and "stdout" not in case and "stdout_base64" not in case:
            raise ValueError(f"{name}: contract requires independent expected stdout")
        if kind == "contract" and case["stderr"] == "exact" and "stderr_text" not in case:
            raise ValueError(f"{name}: exact stderr needs stderr_text")
        if kind == "parity" and not case.get("requires"):
            raise ValueError(f"{name}: parity requires a named external oracle")
        for tool in case.get("requires", []):
            if not NAME.fullmatch(tool):
                raise ValueError(f"{name}: invalid oracle command")
    return suite


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024**2, 768 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**2, 8 * 1024**2))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def sandbox_argv(tree, binary, metadata, mode, script):
    if not shutil.which("bwrap"):
        raise RuntimeError("bubblewrap is required; refusing host execution")
    args = ["bwrap", "--unshare-all", "--unshare-user", "--disable-userns", "--die-with-parent",
            "--new-session", "--cap-drop", "ALL", "--hostname", "parity",
            "--clearenv", "--ro-bind", "/usr", "/usr"]
    for part in ("bin", "sbin", "lib", "lib64"):
        path = Path("/") / part
        if path.is_symlink():
            args += ["--symlink", os.readlink(path), str(path)]
        elif path.exists():
            args += ["--ro-bind", str(path), str(path)]
    args += ["--dir", "/etc"]
    for name in ("passwd", "group", "nsswitch.conf"):
        args += ["--ro-bind", str(metadata / name), "/etc/" + name]
    for name in ("ld.so.cache", "terminfo", "alternatives"):
        if (Path("/etc") / name).exists():
            args += ["--ro-bind", "/etc/" + name, "/etc/" + name]
    args += ["--proc", "/proc", "--remount-ro", "/proc", "--dev", "/dev",
             "--tmpfs", "/tmp", "--dir", "/empty", "--dir", "/runtime",
             "--ro-bind", str(binary), "/runtime/bash-os",
             "--bind", str(tree), "/work", "--chdir", "/work"]
    for key, value in {"LC_ALL": "C", "LANG": "C", "TZ": "UTC",
                       "TERM": "xterm-256color", "HOME": "/tmp",
                       "PATH": "/usr/bin:/bin" if mode == "reference" else "/empty",
                       "BASH_ENV": "", "ENV": ""}.items():
        args += ["--setenv", key, value]
    shell = "/bin/bash" if mode == "reference" else "/runtime/bash-os"
    args += ["--", shell, "--noprofile", "--norc", "-c",
             'set -e; set -o pipefail; umask 022; eval "$1"', "fixture", script]
    return args


def tree_snapshot(tree):
    entries, links, total = {}, {}, 0
    for path in sorted(tree.rglob("*")):
        if len(entries) > 4096:
            raise ValueError("fixture contains too many files")
        info = path.lstat()
        name = str(path.relative_to(tree))
        entry = {"mode": stat.S_IMODE(info.st_mode)}
        if stat.S_ISLNK(info.st_mode):
            entry.update(kind="symlink", target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            entry.update(kind="directory")
        elif stat.S_ISREG(info.st_mode):
            total += info.st_size
            if total > 16 * 1024**2:
                raise ValueError("fixture exceeds size limit")
            entry.update(kind="file", data=base64.b64encode(path.read_bytes()).decode(),
                         hardlink=links.setdefault((info.st_dev, info.st_ino), name))
        elif stat.S_ISFIFO(info.st_mode):
            entry.update(kind="fifo")
        else:
            raise ValueError(f"unsupported fixture type: {name}")
        entries[name] = entry
    return entries


def execute(root, binary, metadata, mode, case):
    root.mkdir()
    tree = root / "tree"
    tree.mkdir()
    args = sandbox_argv(tree, binary, metadata, mode, case["script"])
    with syscall_filter() as seccomp, (root / "stdout").open("wb") as out, (root / "stderr").open("wb") as err:
        args[1:1] = ["--seccomp", str(seccomp.fileno())]
        proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                start_new_session=True, preexec_fn=limits,
                                pass_fds=(seccomp.fileno(),))
        try:
            rc = proc.wait(timeout=case.get("timeout", 5))
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise RuntimeError(f"{mode} exceeded wall-clock limit")
    stdout, stderr = (root / "stdout").read_bytes(), (root / "stderr").read_bytes()
    if stderr.startswith(b"bwrap:"):
        raise RuntimeError("namespace setup failed: " + stderr.decode(errors="replace")[:500])
    result = {"status": rc, "stdout": base64.b64encode(stdout).decode(),
              "stderr": base64.b64encode(stderr).decode(), "tree": tree_snapshot(tree)}
    (root / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def expected_bytes(case, field):
    if field + "_base64" in case:
        return base64.b64decode(case[field + "_base64"], validate=True)
    return case.get(field, "").encode()


def run_suite(suite, binary, output):
    output.mkdir(parents=True, exist_ok=False)
    records = []
    with tempfile.TemporaryDirectory(prefix="loadable-parity-") as tmp:
        metadata = Path(tmp)
        (metadata / "passwd").write_text(f"runner:x:{os.getuid()}:{os.getgid()}::/tmp:/bin/bash\n")
        (metadata / "group").write_text(f"runner:x:{os.getgid()}:\n")
        (metadata / "nsswitch.conf").write_text("passwd: files\ngroup: files\nhosts: files\n")
        # Availability is checked in the same mandatory isolation as fixtures.
        probe = {"script": f"type -t {suite['loadable']}", "timeout": 5}
        availability = execute(output / "availability", binary, metadata, "candidate", probe)
        present = availability["status"] == 0 and base64.b64decode(availability["stdout"]) == b"builtin\n"
        for case in suite["cases"]:
            record = {"id": case["id"], "kind": case["kind"]}
            records.append(record)
            try:
                if case["kind"] == "deferred":
                    record.update(status="DEFERRED", reason=case["reason"])
                elif not present:
                    record.update(status="SKIP" if suite.get("optional", False) else "ERROR",
                                  reason="loadable is not present in the candidate binary")
                else:
                    missing = [x for x in case.get("requires", [])
                               if not shutil.which(x, path="/usr/bin:/bin")]
                    if case["kind"] == "parity" and missing:
                        record.update(status="SKIP", reason="missing oracle: " + ", ".join(missing))
                    else:
                        folder = output / case["id"]
                        folder.mkdir()
                        a = execute(folder / "reference", binary, metadata, "reference", case) if case["kind"] == "parity" else None
                        b = execute(folder / "candidate", binary, metadata, "candidate", case)
                        differences = []
                        valid_reference = True
                        for label, result in (("reference", a), ("candidate", b)):
                            if result is None:
                                continue
                            if result["status"] != case["expected_status"]:
                                differences.append(f"{label} status {result['status']}, expected {case['expected_status']}")
                                if label == "reference": valid_reference = False
                            err = base64.b64decode(result["stderr"])
                            if (case["stderr"] == "empty" and err) or (case["stderr"] == "nonempty" and not err):
                                differences.append(f"{label} stderr policy")
                                if label == "reference": valid_reference = False
                        wanted = base64.b64decode(a["stdout"]) if a else expected_bytes(case, "stdout")
                        if base64.b64decode(b["stdout"]) != wanted:
                            differences.append("stdout bytes")
                        if case["stderr"] == "exact":
                            wanted_err = base64.b64decode(a["stderr"]) if a else case["stderr_text"].encode()
                            if base64.b64decode(b["stderr"]) != wanted_err:
                                differences.append("stderr bytes")
                        if a and case.get("compare_tree", True) and a["tree"] != b["tree"]:
                            differences.append("filesystem contents/modes/links")
                        record.update(status=("ERROR" if not valid_reference else "FAIL") if differences else "PASS",
                                      differences=differences)
            except (OSError, ValueError, RuntimeError) as error:
                record.update(status="ERROR", reason=str(error))
            print(f"{record['status']:8} {suite['loadable']}/{case['id']} "
                  + (record.get("reason") or "; ".join(record.get("differences", []))), flush=True)
    summary = {status: sum(r["status"] == status for r in records)
               for status in ("PASS", "FAIL", "ERROR", "SKIP", "DEFERRED")}
    report = {"loadable": suite["loadable"], "summary": summary, "cases": records}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validate-only", action="store_true")
    args = parser.parse_args()
    suite = validate(json.loads(args.suite.read_text()))
    if args.validate_only:
        print(f"valid: {suite['loadable']} ({len(suite['cases'])} cases)")
        return 0
    report = run_suite(suite, args.binary.resolve(strict=True), args.output.resolve())
    print(json.dumps(report["summary"], sort_keys=True))
    return int(bool(report["summary"]["FAIL"] or report["summary"]["ERROR"]))


if __name__ == "__main__":
    raise SystemExit(main())
