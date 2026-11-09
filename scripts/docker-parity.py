#!/usr/bin/env python3
"""Run identical inputs in two Docker images and retain replayable evidence."""
import argparse
import base64
import concurrent.futures
import csv
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import termios
import time
import tty
import uuid

ROOT = Path(__file__).resolve().parents[1]
PROMPT = b"parity> "
ENV = {
    "HOME": "/tmp", "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
    "TERM": "xterm-256color", "BASH_ENV": "", "ENV": "",
    "INPUTRC": "/dev/null", "HISTFILE": "/dev/null", "PROMPT_COMMAND": "",
    "PS1": PROMPT.decode(), "PS2": "more> ",
    "PATH": "/opt/bash-reference/bin:/opt/util-linux-reference/bin:/usr/local/sbin:"
            "/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games",
}


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def say(text, stream=None):
    """Print status; a hung-up terminal must not change the exit status."""
    stream = stream or sys.stdout
    try:
        print(text, file=stream, flush=True)
    except OSError:
        # Point the descriptor at /dev/null so the shutdown flush cannot fail either.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, stream.fileno())
        os.close(devnull)


def docker(*args, timeout=30):
    return subprocess.run(["docker", *map(str, args)], capture_output=True,
                          timeout=timeout, check=True).stdout


def mount(source, target, readonly=False):
    out = io.StringIO()
    csv.writer(out, lineterminator="").writerow(
        ["type=bind", "source=" + str(source), "target=" + target]
        + (["readonly"] if readonly else []))
    return out.getvalue()


def safe_path(path):
    """Resolve a work path, rejecting archive-only storage named in BASH_OS_ARCHIVE_PATHS."""
    path = Path(path).expanduser().resolve()
    for entry in os.environ.get("BASH_OS_ARCHIVE_PATHS", "").split(":"):
        if not entry:
            continue
        root = Path(entry).expanduser().resolve()
        if path == root or root in path.parents:
            raise argparse.ArgumentTypeError(
                f"{path} is under archive-only storage {root} (BASH_OS_ARCHIVE_PATHS)")
    return path


class owner_access:
    """Temporarily add owner permission bits, then restore the exact mode.

    Both sides run as the runner's user, so the runner owns every entry and can
    read a tree the test made unreadable (for example `chmod 0 dir`). Skipping
    such entries would hide their contents from the comparison on both sides.
    """
    def __init__(self, path, mode, bits):
        self.path, self.mode, self.bits = path, mode, bits

    def __enter__(self):
        if self.mode & self.bits != self.bits:
            os.chmod(self.path, self.mode | self.bits)

    def __exit__(self, *_):
        if self.mode & self.bits != self.bits:
            os.chmod(self.path, self.mode)


def snapshot(root):
    """Compare bytes, permissions, link topology and special-file types, not times."""
    result = {}
    links = {}
    def visit(path, rel):
        info = path.lstat()
        mode = stat.S_IMODE(info.st_mode)
        item = {"mode": mode}
        result[rel] = item
        if stat.S_ISLNK(info.st_mode):
            item.update(type="symlink", target=os.readlink(path))
        elif stat.S_ISDIR(info.st_mode):
            item.update(type="directory")
            with owner_access(path, mode, stat.S_IRUSR | stat.S_IXUSR):
                for name in sorted(os.listdir(path)):
                    visit(path / name, name if rel == "." else rel + "/" + name)
        elif stat.S_ISREG(info.st_mode):
            with owner_access(path, mode, stat.S_IRUSR), path.open("rb") as f:
                digest = hashlib.file_digest(f, "sha256").hexdigest()
            item.update(type="file", size=info.st_size, sha256=digest,
                        hardlink=links.setdefault((info.st_dev, info.st_ino), rel))
        else:
            item.update(type=stat.S_IFMT(info.st_mode), device=info.st_rdev)
    visit(root, ".")
    return result


def copy_fixture(source, destination):
    links = {}
    def copy_file(src, dst):
        info = os.stat(src)
        key = (info.st_dev, info.st_ino)
        if key in links:
            os.link(links[key], dst)
        else:
            shutil.copy2(src, dst)
            links[key] = dst
        return dst
    shutil.copytree(source, destination, symlinks=True, copy_function=copy_file)


def image_info(name):
    item = json.loads(docker("image", "inspect", name))[0]
    return {"requested": name, "id": item["Id"],
            "repo_digests": item.get("RepoDigests", []), "config": item["Config"]}


class Container:
    def __init__(self, image, directory, script, shell_args, options, interactive=False):
        self.name = "bash-parity-" + uuid.uuid4().hex
        self.directory = directory
        self.process = None
        self.master = None
        self.handles = []
        self.created = False
        directory.mkdir(parents=True)
        tree = directory / "tree"
        if options.fixture:
            copy_fixture(options.fixture, tree)
        else:
            tree.mkdir()
        self.tree = tree
        args = ["create", "--name", self.name, "--interactive", "--pull=never",
                "--hostname", "parity", "--network=none", "--read-only",
                "--log-driver=none", "--user", f"{os.getuid()}:{os.getgid()}",
                "--pids-limit", "256", "--memory", options.memory, "--cpus", options.cpus,
                "--tmpfs", "/tmp:rw,nosuid,size=128m,mode=1777", "--workdir", "/work",
                "--mount", mount(tree, "/work")]
        if interactive:
            args += ["--tty"]
        if script:
            args += ["--mount", mount(script, "/parity/input.sh", True)]
        for key, value in ENV.items():
            args += ["--env", key + "=" + value]
        args += [image["id"], "--noprofile", "--norc", *shell_args]
        # Existing shell entrypoints may include --noprofile/--norc already.
        # Preserve them; the repeated shell flags are harmless.
        docker(*args)
        self.created = True
        write_json(directory / "container.json", {"name": self.name, "create": args})

    def state(self):
        return json.loads(docker("inspect", self.name))[0]["State"]

    def outcome(self, timed_out=False):
        state = self.state()
        valid = (state["Status"] == "exited" and not state.get("Error")
                 and not state.get("OOMKilled") and not timed_out
                 and self.process.returncode == state["ExitCode"])
        result = {"exit_status": state["ExitCode"], "timed_out": timed_out,
                  "valid": valid, "docker_status": self.process.returncode,
                  "state": state}
        write_json(self.directory / "outcome.json", result)
        return result

    def batch(self, data, timeout):
        with (self.directory / "stdout").open("wb") as out, \
                (self.directory / "stderr").open("wb") as err:
            self.process = subprocess.Popen(["docker", "start", "--attach", "--interactive",
                                             self.name], stdin=subprocess.PIPE,
                                            stdout=out, stderr=err)
            timed_out = False
            try:
                self.process.communicate(data, timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                self.stop()
                self.process.communicate(timeout=10)
        return self.outcome(timed_out)

    def start_terminal(self):
        self.master, slave = pty.openpty()
        tty.setraw(slave)
        errors = (self.directory / "docker-stderr").open("wb")
        self.handles.append(errors)
        try:
            self.process = subprocess.Popen(["docker", "start", "--attach", "--interactive",
                                             self.name], stdin=slave, stdout=slave, stderr=errors)
        finally:
            os.close(slave)
        os.set_blocking(self.master, False)
        self.transcript = (self.directory / "terminal").open("wb")
        self.handles.append(self.transcript)
        self.buffer = bytearray()
        self.cursor = 0

    def read(self):
        try:
            data = os.read(self.master, 65536)
        except (BlockingIOError, OSError):
            return b""
        self.transcript.write(data)
        self.transcript.flush()
        self.buffer.extend(data)
        return data

    def stop(self):
        if self.created:
            subprocess.run(["docker", "kill", self.name], capture_output=True, timeout=15)
        if self.process and self.process.poll() is None:
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)

    def close(self):
        try:
            if self.created:
                subprocess.run(["docker", "rm", "--force", self.name],
                               capture_output=True, timeout=15, check=True)
        finally:
            if self.process and self.process.poll() is None:
                self.process.kill()
                self.process.wait(timeout=5)
            for handle in self.handles:
                handle.close()
            if self.master is not None:
                os.close(self.master)


class DockerSocket(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=10)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def resize(containers, rows, cols):
    if not (1 <= rows <= 1000 and 1 <= cols <= 1000):
        raise ValueError("terminal dimensions must be between 1 and 1000")
    endpoint = os.environ.get("DOCKER_HOST")
    if not endpoint or os.environ.get("DOCKER_CONTEXT"):
        context = json.loads(docker("context", "inspect"))[0]
        endpoint = context["Endpoints"]["docker"]["Host"]
    if not endpoint.startswith("unix://"):
        raise ValueError("PTY resize currently requires a local Unix-socket Docker context")
    for container in containers:
        conn = DockerSocket(endpoint[7:])
        try:
            conn.request("POST", f"/containers/{container.name}/resize?h={rows}&w={cols}")
            reply = conn.getresponse()
            body = reply.read()
            if reply.status not in (200, 201, 204):
                raise RuntimeError(f"Docker resize failed: {reply.status} {body!r}")
        finally:
            conn.close()


def pump(containers, timeout=0.05, display=False):
    ready, _, _ = select.select([c.master for c in containers], [], [], timeout)
    for container in containers:
        if container.master in ready:
            data = container.read()
            if display and container is containers[0] and data:
                os.write(sys.stdout.fileno(), data)


def broadcast(containers, data, timeout, display=False):
    pending = {c.master: memoryview(data) for c in containers if data}
    deadline = time.monotonic() + timeout
    while pending:
        if time.monotonic() >= deadline:
            raise TimeoutError("terminal input backpressure")
        pump(containers, 0, display)
        _, ready, _ = select.select([], list(pending), [], 0.02)
        for container in containers:
            fd = container.master
            if fd not in pending:
                continue
            if container.process.poll() is not None:
                raise BrokenPipeError("shell exited before consuming the event input")
            if fd in ready:
                try:
                    count = os.write(fd, pending[fd][:65536])
                except BlockingIOError:
                    continue
                pending[fd] = pending[fd][count:]
                if not pending[fd]:
                    del pending[fd]


def until(containers, predicate, timeout, display=False):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() >= deadline:
            raise TimeoutError("interactive checkpoint or exit timed out")
        pump(containers, min(0.05, max(0, deadline - time.monotonic())), display)


def expect(containers, needle, timeout):
    if not needle:
        raise ValueError("expect must not be empty")
    until(containers, lambda: all(needle in c.buffer[c.cursor:] for c in containers), timeout)
    for container in containers:
        container.cursor = container.buffer.index(needle, container.cursor) + len(needle)


def event_data(event, key):
    if key + "_b64" in event:
        return base64.b64decode(event[key + "_b64"], validate=True)
    return event[key].encode()


def replay(containers, events, timeout):
    for event in events:
        kind = set(event) - {"timeout"}
        limit = event.get("timeout", timeout)
        if kind in ({"send"}, {"send_b64"}):
            broadcast(containers, event_data(event, "send"), limit)
        elif kind in ({"expect"}, {"expect_b64"}):
            expect(containers, event_data(event, "expect"), limit)
        elif kind == {"resize"}:
            resize(containers, *event["resize"])
        elif kind == {"signal"}:
            sig = event["signal"]
            if sig not in ("SIGINT", "SIGTERM", "SIGHUP", "SIGWINCH"):
                raise ValueError("unsupported replay signal")
            for container in containers:
                docker("kill", "--signal", sig, container.name)
        elif kind == {"eof"} and event["eof"] is True:
            broadcast(containers, b"\x04", limit)
        elif kind == {"sleep"}:
            duration = float(event["sleep"])
            if not 0 <= duration <= timeout:
                raise ValueError("sleep must be within the per-event timeout")
            end = time.monotonic() + duration
            while time.monotonic() < end:
                pump(containers)
        else:
            raise ValueError(f"unsupported event: {event!r}")
    until(containers, lambda: all(c.process.poll() is not None for c in containers), timeout)
    # Drain bytes delivered immediately before the attach clients exited.
    for _ in range(3):
        pump(containers)


def live(containers, events, timeout):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("live mode needs a terminal for stdin and stdout")
    events.append({"expect": PROMPT.decode()})
    expect(containers, PROMPT, timeout)
    os.write(sys.stdout.fileno(), containers[0].buffer)
    def follow_terminal_size():
        # A terminal that reports no size (0x0) leaves both shells at Docker's default.
        size = os.get_terminal_size()
        if not (size.lines and size.columns):
            return None
        resize(containers, size.lines, size.columns)
        return {"resize": [size.lines, size.columns]}
    initial_size = follow_terminal_size()
    if initial_size:
        events.append(initial_size)
    old = termios.tcgetattr(sys.stdin.fileno())
    resized = [False]
    previous_handler = signal.signal(signal.SIGWINCH, lambda *_: resized.__setitem__(0, True))
    last = time.monotonic()
    def record(event):
        nonlocal last
        now = time.monotonic()
        # Long human pauses need not make the replay exceed its event timeout.
        delay = now - last
        while delay > 0:
            part = min(delay, timeout)
            events.append({"sleep": part})
            delay -= part
        events.append(event)
        last = now
    try:
        tty.setraw(sys.stdin.fileno())
        while any(c.process.poll() is None for c in containers):
            pump(containers, display=True)
            if resized[0]:
                resized[0] = False
                event = follow_terminal_size()
                if event:
                    record(event)
            ready, _, _ = select.select([sys.stdin], [], [], 0.01)
            if ready:
                data = os.read(sys.stdin.fileno(), 4096)
                if not data or b"\x1d" in data:
                    raise KeyboardInterrupt("live session stopped with Ctrl-]")
                broadcast(containers, data, timeout, display=True)
                record({"send_b64": base64.b64encode(data).decode()})
            if any(c.process.poll() is not None for c in containers):
                until(containers, lambda: all(c.process.poll() is not None for c in containers),
                      timeout, display=True)
        for _ in range(3):
            pump(containers, display=True)
    finally:
        signal.signal(signal.SIGWINCH, previous_handler)
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
        except termios.error:
            pass  # the terminal was hung up; there is nothing left to restore


def compare(containers, outcomes, interactive, expected):
    differences = []
    for side, outcome in zip(("reference", "candidate"), outcomes):
        if not outcome["valid"]:
            differences.append(side + " did not complete normally")
    if outcomes[0]["exit_status"] != expected:
        differences.append(f"reference exit {outcomes[0]['exit_status']}, expected {expected}")
    if outcomes[0]["exit_status"] != outcomes[1]["exit_status"]:
        differences.append("exit status")
    for stream in (["terminal"] if interactive else ["stdout", "stderr"]):
        left, right = [(c.directory / stream).read_bytes() for c in containers]
        if left != right:
            offset = next((i for i, (a, b) in enumerate(zip(left, right)) if a != b),
                          min(len(left), len(right)))
            differences.append(f"{stream} bytes (first difference at offset {offset})")
    trees = []
    for container in containers:
        tree = snapshot(container.tree)
        write_json(container.directory / "tree.json", tree)
        trees.append(tree)
    if trees[0] != trees[1]:
        differences.append("filesystem contents/modes/links")
    return differences


def preflight(images, output, options):
    probes = []
    probe_options = argparse.Namespace(**vars(options))
    probe_options.fixture = None
    try:
        for side, image in zip(("reference", "candidate"), images):
            probe = Container(image, output / (side + "-identity"), None,
                              ["-c", 'printf "%s\\n" "$BASH_VERSION"; sha256sum /proc/$$/exe'],
                              probe_options)
            probes.append(probe)
            outcome = probe.batch(b"", options.timeout)
            lines = (probe.directory / "stdout").read_text().splitlines()
            if not outcome["valid"] or outcome["exit_status"] or len(lines) != 2:
                raise RuntimeError(f"{side} image identity probe failed")
            if not re.fullmatch(r"[0-9a-f]{64}  .+", lines[1]):
                raise RuntimeError(f"{side} did not return an executable SHA-256")
            image["bash_version"] = lines[0]
            image["executable_sha256"] = lines[1].split()[0]
        if not re.match(r"^5\.3\.20(?:\(|-|$)", images[0]["bash_version"]):
            raise ValueError("reference must run GNU Bash 5.3.20")
    finally:
        for probe in probes:
            probe.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "replay", "live", "suite"))
    parser.add_argument("--workspace", required=True, type=safe_path)
    parser.add_argument("--output", type=safe_path, help="new result directory; default WORKSPACE/results/TIMESTAMP")
    parser.add_argument("--reference", default="bash-os:parity-debian")
    parser.add_argument("--candidate", default="bash-os:parity-bash-os")
    parser.add_argument("--script", type=Path)
    parser.add_argument("--stdin", type=Path, help="binary data for the script, separate from shell program input")
    parser.add_argument("--arg", action="append", default=[])
    parser.add_argument("--events", type=Path)
    parser.add_argument("--fixture", type=safe_path)
    parser.add_argument("--timeout", type=float, default=30, help="seconds per run/checkpoint (suite: whole collector)")
    parser.add_argument("--expect-status", type=int, default=0)
    parser.add_argument("--memory", default="512m")
    parser.add_argument("--cpus", default="2")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("timeout must be positive")
    if args.mode == "run" and not args.script:
        parser.error("run requires --script")
    if args.mode == "replay" and not args.events:
        parser.error("replay requires --events")
    if args.mode != "run" and (args.script or args.stdin or args.arg):
        parser.error("--script, --stdin and --arg are only valid in run mode")
    if args.mode != "replay" and args.events:
        parser.error("--events is only valid in replay mode")
    if args.mode == "live" and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        parser.error("live requires a terminal")
    args.workspace.mkdir(parents=True, exist_ok=True)
    output = args.output or args.workspace / "results" / (time.strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:8])
    if args.fixture and (args.fixture == output or args.fixture in output.parents):
        parser.error("result directory must be outside the input fixture")
    output.mkdir(parents=True, exist_ok=False)
    print(f"Results: {output}", flush=True)
    containers, outcomes, events = [], [], []
    metadata = {"mode": args.mode, "environment": ENV, "options": vars(args).copy(),
                "output": str(output), "status": "incomplete"}
    metadata["options"] = {k: str(v) if isinstance(v, Path) else v for k, v in metadata["options"].items()}
    write_json(output / "run.json", metadata)
    report = {"passed": False, "status": "incomplete", "differences": []}
    exit_code = 2
    try:
        images = [image_info(args.reference), image_info(args.candidate)]
        metadata["images"] = images
        metadata["docker"] = json.loads(docker("version", "--format", "{{json .}}"))
        preflight(images, output, args)
        if args.fixture:
            copy_fixture(args.fixture, output / "fixture")
            args.fixture = output / "fixture"
        else:
            (output / "fixture").mkdir()
            args.fixture = output / "fixture"
        # Preserve the runner and its suite dependencies with the input capture.
        (output / "scripts").mkdir()
        (output / "tests").mkdir()
        saved_runner = output / "scripts/docker-parity.py"
        shutil.copyfile(Path(__file__), saved_runner)
        metadata["runner_sha256"] = hashlib.sha256(saved_runner.read_bytes()).hexdigest()
        if args.mode == "suite":
            for name in ("bash-gnu-parity.sh", "compare-parity.py"):
                shutil.copyfile(ROOT / "tests" / name, output / "tests" / name)
        replay_command = [sys.executable, str(saved_runner),
                          "replay" if args.mode == "live" else args.mode,
                          "--workspace", str(args.workspace),
                          "--reference", images[0]["id"], "--candidate", images[1]["id"],
                          "--fixture", str(args.fixture), "--timeout", str(args.timeout),
                          "--expect-status", str(args.expect_status),
                          "--memory", args.memory, "--cpus", args.cpus]
        if args.mode == "run":
            replay_command += ["--script", str(output / "input.sh"), "--stdin", str(output / "stdin")]
            replay_command += ["--arg=" + arg for arg in args.arg]
        elif args.mode in ("live", "replay"):
            replay_command += ["--events", str(output / "events.json")]
        write_json(output / "replay-command.json", replay_command)
        write_json(output / "run.json", metadata)
        script = None
        data = args.stdin.read_bytes() if args.stdin else b""
        (output / "stdin").write_bytes(data)
        if args.mode in ("run", "suite"):
            script = output / "input.sh"
            origin = args.script if args.mode == "run" else ROOT / "tests/bash-gnu-parity.sh"
            shutil.copyfile(origin, script)
            script.chmod(0o644)
        interactive = args.mode in ("live", "replay")
        for side, image in zip(("reference", "candidate"), images):
            if args.mode == "suite":
                shell_args = ["/parity/input.sh", "/work/result", "gnu" if side == "reference" else "builtins"]
            else:
                shell_args = ["-i"] if interactive else ["/parity/input.sh", *args.arg]
            container = Container(image, output / side, script, shell_args, args, interactive)
            containers.append(container)
        if interactive:
            for container in containers:
                container.start_terminal()
            if args.mode == "replay":
                events = json.loads(args.events.read_text())
                write_json(output / "events.json", events)
                replay(containers, events, args.timeout)
            else:
                live(containers, events, args.timeout)
            outcomes = [c.outcome() for c in containers]
        else:
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
            try:
                outcomes = list(pool.map(lambda c: c.batch(data, args.timeout), containers))
            except BaseException:
                for container in containers:
                    container.stop()
                raise
            finally:
                pool.shutdown(wait=True, cancel_futures=True)
        if args.mode == "suite":
            if any(not o["valid"] for o in outcomes):
                raise RuntimeError("collector timed out or Docker failed")
            comparator = output / "compare-parity.py"
            shutil.copyfile(ROOT / "tests/compare-parity.py", comparator)
            with (output / "comparison.log").open("wb") as log:
                result = subprocess.run([sys.executable, str(comparator),
                                         str(containers[0].tree / "result"),
                                         str(containers[1].tree / "result")], stdout=log, stderr=log,
                                        timeout=args.timeout)
            summary_path = containers[1].tree / "result/comparison.json"
            if result.returncode not in (0, 1) or not summary_path.exists():
                raise RuntimeError("collector incomplete or comparator failed; see comparison.log")
            summary = json.loads(summary_path.read_text())
            write_json(output / "comparison.json", summary)
            differences = [c["case"] + ": " + ", ".join(c["differences"])
                           for c in summary["cases"] if not c["passed"]]
            if any(o["exit_status"] != 0 for o in outcomes):
                differences.append("collector reported failed assertions")
            if result.returncode and not differences:
                raise RuntimeError("comparator returned failure without differences")
        else:
            differences = compare(containers, outcomes, interactive, args.expect_status)
        report.update(passed=not differences, status="complete", differences=differences, outcomes=outcomes)
        exit_code = 1 if differences else 0
    except (Exception, KeyboardInterrupt) as error:
        report.update(status="error", error=f"{type(error).__name__}: {error}")
        if isinstance(error, subprocess.CalledProcessError):
            report["detail"] = error.stderr.decode(errors="replace") if error.stderr else ""
        for container in containers:
            if container.process:
                container.stop()
                try:
                    outcomes.append(container.outcome(isinstance(error, TimeoutError)))
                except Exception:
                    pass
        report["outcomes"] = outcomes
        say(report["error"], sys.stderr)
    finally:
        if args.mode in ("live", "replay"):
            write_json(output / "events.json", events)
        cleanup = []
        for container in containers:
            try:
                container.close()
            except Exception as error:
                cleanup.append(str(error))
        if cleanup:
            report.update(passed=False, status="error", cleanup_errors=cleanup)
            exit_code = 2
        metadata["status"] = report["status"]
        write_json(output / "run.json", metadata)
        write_json(output / "report.json", report)
    say(("PASS" if report["passed"] else "FAIL") + f": {output / 'report.json'}")
    for difference in report["differences"]:
        say("  " + difference)
    return exit_code


if __name__ == "__main__":
    def terminate(_signal, _frame):
        raise KeyboardInterrupt("parity runner terminated")
    signal.signal(signal.SIGTERM, terminate)
    # Closing the terminal of a live session must still remove both containers.
    # Keep an inherited ignore (nohup), which asks to survive the hangup.
    if signal.getsignal(signal.SIGHUP) == signal.SIG_DFL:
        signal.signal(signal.SIGHUP, terminate)
    sys.exit(main())
