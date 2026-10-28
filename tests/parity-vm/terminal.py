#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded controlling-PTY driver. Imported only by the VM guest runner.

Each side runs as the leader of a new session whose controlling terminal is
a fresh PTY of a fixed size. Steps are executed in order:

  {"expect": REGEX}            wait for REGEX in the raw output after the
                               previous match (bytes, escape sequences included)
  {"send": TEXT}               write TEXT (UTF-8) to the terminal
  {"send_base64": B64}         write arbitrary bytes
  {"key": NAME}                write the bytes a VT100/xterm terminal sends
                               for NAME, honouring the cursor-key mode
                               (DECCKM) the program last selected
  {"resize": [ROWS, COLS]}     TIOCSWINSZ on the PTY; the kernel sends SIGWINCH
                               to the foreground process group
  {"settle_ms": N}             keep reading for N ms (N <= 500)
  {"quiet_ms": N}              read until no output arrives for N ms (N <= 1000)
  {"screen": SPEC}             wait until the decoded screen satisfies SPEC:
                               "rows" {"INDEX": REGEX} (negative INDEX counts
                               from the bottom), "contains" [REGEX] (some row),
                               "lacks" [REGEX] (no row), "cursor" [ROW, COL]
  {"termios": SPEC}            wait until the PTY modes satisfy SPEC: "set" and
                               "clear" lists of flag names, "cc" {"VMIN": N}
  {"output_lacks": REGEX}      REGEX must not occur anywhere in the output so far
  {"foreground_job": [SIG...]} wait until the terminal's foreground process
                               group is not the shell's and none of its members
                               ignores or blocks the named signals, so a
                               keyboard signal sent next reaches a running job
  {"hangup": true}             close the master side; the kernel hangs up the
                               session. Only "expect"-free steps may follow.

Screen assertions use the independent pyte ECMA-48 decoder. When it is not
installed they fail with an error; they never pass silently.
"""
import base64
import errno
import fcntl
import grp
import os
import pty
import re
import resource
import select
import signal
import struct
import subprocess
import termios
import time

try:
    import pyte
except ImportError:  # reported per case; screen steps then fail
    pyte = None

OUTPUT_LIMIT = 2 * 1024**2
MAX_TIMEOUT = 60
STEP_KEYS = {"expect", "send", "send_base64", "key", "resize", "settle_ms", "quiet_ms",
             "screen", "termios", "output_lacks", "foreground_job", "hangup"}
CASE_KEYS = {"size", "steps", "answer_queries", "allow_stray_processes"}

# Bytes sent by xterm for each key: (normal cursor mode, application cursor mode).
KEYS = {
    "up": (b"\x1b[A", b"\x1bOA"), "down": (b"\x1b[B", b"\x1bOB"),
    "right": (b"\x1b[C", b"\x1bOC"), "left": (b"\x1b[D", b"\x1bOD"),
    "home": (b"\x1b[H", b"\x1bOH"), "end": (b"\x1b[F", b"\x1bOF"),
    "insert": (b"\x1b[2~",) * 2, "delete": (b"\x1b[3~",) * 2,
    "page_up": (b"\x1b[5~",) * 2, "page_down": (b"\x1b[6~",) * 2,
    "backspace": (b"\x7f",) * 2, "enter": (b"\r",) * 2, "tab": (b"\t",) * 2,
    "escape": (b"\x1b",) * 2,
}
FLAGS = {name: (index, getattr(termios, name)) for index, names in (
    (0, ("IGNBRK", "BRKINT", "IGNPAR", "PARMRK", "INPCK", "ISTRIP", "INLCR", "IGNCR",
         "ICRNL", "IXON", "IXANY", "IXOFF", "IMAXBEL", "IUTF8")),
    (1, ("OPOST", "ONLCR", "OCRNL", "ONOCR", "ONLRET")),
    (2, ("CSIZE", "CSTOPB", "CREAD", "PARENB", "HUPCL", "CLOCAL")),
    (3, ("ISIG", "ICANON", "ECHO", "ECHOE", "ECHOK", "ECHONL", "ECHOCTL", "ECHOKE",
         "NOFLSH", "TOSTOP", "IEXTEN"))) for name in names}
CC = {name: getattr(termios, name) for name in (
    "VINTR", "VQUIT", "VERASE", "VKILL", "VEOF", "VTIME", "VMIN", "VSTART", "VSTOP",
    "VSUSP", "VEOL", "VREPRINT", "VDISCARD", "VWERASE", "VLNEXT", "VEOL2")}
# Documented initial control characters, so that both sides start from the same
# state regardless of kernel defaults.
INITIAL_CC = {"VINTR": 3, "VQUIT": 0x1c, "VERASE": 0x7f, "VKILL": 0x15, "VEOF": 4,
              "VTIME": 0, "VMIN": 1, "VSTART": 0x11, "VSTOP": 0x13, "VSUSP": 0x1a,
              "VEOL": 0, "VREPRINT": 0x12, "VDISCARD": 0x0f, "VWERASE": 0x17,
              "VLNEXT": 0x16, "VEOL2": 0}
CURSOR_MODE = re.compile(rb"\x1b\[\?([0-9;]*)([hl])")
# Per-cell rendition fields asserted against pyte's Char: colours are pyte names
# ("default", "red", ...) or six-digit lowercase hex for 256-colour/truecolour.
CELL_FIELDS = {"data": str, "fg": str, "bg": str, "bold": bool, "italics": bool,
               "underscore": bool, "strikethrough": bool, "reverse": bool}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def dimensions(value):
    check(isinstance(value, list) and len(value) == 2 and
          all(type(n) is int and 1 <= n <= 500 for n in value), "invalid terminal dimensions")


def regex(value, what):
    check(isinstance(value, str), what + " must be text")
    re.compile(value.encode())


def validate_case(case):
    """Validate the PTY-specific fields of a fixture; raises ValueError."""
    dimensions(case.get("size", [24, 80]))
    for key in ("answer_queries", "allow_stray_processes"):
        if key in case:
            check(type(case[key]) is bool, key + " must be boolean")
    steps = case.get("steps")
    check(isinstance(steps, list) and len(steps) <= 128, "invalid PTY steps")
    hung_up = False
    for step in steps:
        check(isinstance(step, dict) and len(step) == 1 and set(step) <= STEP_KEYS,
              "each PTY step needs exactly one action: " + repr(step))
        (action, value), = step.items()
        check(not hung_up or action in ("settle_ms", "quiet_ms"),
              "only settle/quiet steps may follow a hangup")
        if action in ("expect", "output_lacks"):
            regex(value, action)
        elif action == "send":
            check(isinstance(value, str) and 0 < len(value.encode()) <= 65536, "invalid PTY input")
        elif action == "send_base64":
            check(isinstance(value, str) and 0 < len(base64.b64decode(value, validate=True)) <= 65536,
                  "invalid PTY input")
        elif action == "key":
            check(value in KEYS, "unknown key name: " + repr(value))
        elif action == "resize":
            dimensions(value)
        elif action == "settle_ms":
            check(type(value) in (int, float) and 0 <= value <= 500, "invalid PTY settle interval")
        elif action == "quiet_ms":
            check(type(value) in (int, float) and 10 <= value <= 1000, "invalid PTY quiet interval")
        elif action == "screen":
            check(isinstance(value, dict) and value and
                  not set(value) - {"rows", "contains", "lacks", "cursor", "cells"}, "invalid screen assertion")
            rows = value.get("rows", {})
            check(isinstance(rows, dict), "screen rows must be an object")
            for index, pattern in rows.items():
                check(re.fullmatch(r"-?[0-9]{1,3}", index) is not None, "invalid screen row index")
                regex(pattern, "screen row")
            for key in ("contains", "lacks"):
                check(isinstance(value.get(key, []), list), "screen " + key + " must be a list")
                for pattern in value.get(key, []):
                    regex(pattern, "screen " + key)
            check(isinstance(value.get("cells", []), list) and len(value.get("cells", [])) <= 256,
                  "screen cells must be a list")
            for cell in value.get("cells", []):
                check(isinstance(cell, dict) and type(cell.get("row")) is int and type(cell.get("col")) is int
                      and cell["col"] >= 0 and set(cell) - {"row", "col"} and
                      not set(cell) - {"row", "col"} - set(CELL_FIELDS), "invalid screen cell: " + repr(cell))
                for name, kind in CELL_FIELDS.items():
                    if name in cell:
                        check(type(cell[name]) is kind, "screen cell " + name + " must be " + kind.__name__)
            if "cursor" in value:
                check(isinstance(value["cursor"], list) and len(value["cursor"]) == 2 and
                      all(type(n) is int and n >= 0 for n in value["cursor"]), "invalid cursor position")
        elif action == "termios":
            check(isinstance(value, dict) and value and not set(value) - {"set", "clear", "cc"},
                  "invalid termios assertion")
            for key in ("set", "clear"):
                check(isinstance(value.get(key, []), list) and
                      all(name in FLAGS for name in value.get(key, [])), "unknown termios flag")
            cc = value.get("cc", {})
            check(isinstance(cc, dict) and all(name in CC and type(n) is int and 0 <= n <= 255
                                               for name, n in cc.items()), "invalid termios cc")
        elif action == "foreground_job":
            check(isinstance(value, list) and value and all(
                isinstance(name, str) and name.startswith("SIG") and
                isinstance(getattr(signal, name, None), signal.Signals) for name in value),
                "foreground_job needs a list of signal names")
        elif action == "hangup":
            check(value is True, "hangup must be true")
            hung_up = True
    return case


def child_limits(file_size_limit=8 * 1024**2, root=False):
    resource.setrlimit(resource.RLIMIT_CPU, (15, 15))
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_limit, file_size_limit))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if root:
        # Privileged fixtures keep uid 0, confined to the per-side namespaces
        # that guest.privileged() creates.
        return
    os.setgroups([])
    os.setgid(2000)
    os.setuid(2000)


def modes(attrs):
    """JSON form of a tcgetattr() list, with VMIN/VTIME normalized to integers."""
    cc = [value if isinstance(value, int) else value[0] for value in attrs[6]]
    return {"iflag": attrs[0], "oflag": attrs[1], "cflag": attrs[2], "lflag": attrs[3],
            "ispeed": attrs[4], "ospeed": attrs[5], "cc": cc,
            "flags": sorted(name for name, (index, mask) in FLAGS.items()
                            if name != "CSIZE" and attrs[index] & mask == mask)}


def mode_changes(before, after):
    names = sorted(set(before["flags"]) ^ set(after["flags"]))
    names += [name for name, index in sorted(CC.items()) if before["cc"][index] != after["cc"][index]]
    for field in ("cflag", "ispeed", "ospeed"):
        if before[field] != after[field]:
            names.append(field)
    return names


def initial_modes(fd):
    attrs = termios.tcgetattr(fd)
    attrs[0] |= termios.IUTF8  # the fixture locale is C.UTF-8
    for name, value in INITIAL_CC.items():
        attrs[6][CC[name]] = bytes([value])
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def set_subreaper():
    """Orphaned descendants reparent to this guest process, so they can be found."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_CHILD_SUBREAPER = 36
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER)")


def owned_processes(leader):
    """PIDs left in the fixture's session or process group, or orphaned to us."""
    found = []
    me = os.getpid()
    for entry in os.listdir("/proc"):
        if not entry.isdigit() or int(entry) in (leader, me):
            continue
        try:
            with open("/proc/" + entry + "/stat", "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        name = data[data.index(b"(") + 1:data.rindex(b")")].decode(errors="replace")
        fields = data[data.rindex(b")") + 2:].split()
        state, ppid, pgrp, session = fields[0], int(fields[1]), int(fields[2]), int(fields[3])
        if state == b"Z" and ppid != me:
            continue
        if leader in (pgrp, session) or ppid == me:
            found.append({"pid": int(entry), "name": name, "state": state.decode()})
    return found


def cleanup(leader):
    """SIGKILL the processes the fixture left behind and reap those we own."""
    strays = []
    for _ in range(10):
        current = [p for p in owned_processes(leader) if p["state"] != "Z"]
        zombies = [p for p in owned_processes(leader) if p["state"] == "Z"]
        for process in zombies:
            try:
                os.waitpid(process["pid"], os.WNOHANG)
            except ChildProcessError:
                pass
        if not current:
            break
        for process in current:
            if process["pid"] not in [s["pid"] for s in strays]:
                strays.append(process)
            try:
                os.kill(process["pid"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        time.sleep(0.02)
        for process in current:
            try:
                os.waitpid(process["pid"], os.WNOHANG)
            except ChildProcessError:
                pass
    return strays


class Screen(pyte.Screen if pyte else object):
    """pyte screen that queues replies to device status/attribute queries."""

    def __init__(self, columns, lines):
        super().__init__(columns, lines)
        self.replies = bytearray()

    def write_process_input(self, data):
        self.replies.extend(data.encode())

    def select_graphic_rendition(self, *attrs, private=False):
        # CSI > Ps m (xterm modifyOtherKeys, sent by vim) is not a rendition
        # change; pyte 0.8.0 passes private=True and its own method rejects it.
        if not private:
            super().select_graphic_rendition(*attrs)


class Session:
    def __init__(self, master, slave, rows, columns, deadline, answer_queries):
        self.master = master
        self.slave = slave
        self.deadline = deadline
        self.captured = bytearray()
        self.answer = answer_queries
        self.screen = self.stream = None
        self.decoder_error = None
        if pyte:
            self.screen = Screen(columns, rows)
            self.stream = pyte.ByteStream(self.screen)

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError("PTY wall-clock limit")
        return left

    def take(self, block):
        self.captured.extend(block)
        if len(self.captured) > OUTPUT_LIMIT:
            raise RuntimeError("PTY output limit")
        if self.stream:
            try:
                self.stream.feed(block)
            except Exception as exc:  # keep the raw capture; screen steps then fail
                self.decoder_error = "screen decoder failed at offset %d: %s: %s" % (
                    len(self.captured) - len(block), type(exc).__name__, exc)
                self.stream = None
                return
            if self.answer and self.screen.replies:
                replies = bytes(self.screen.replies)
                self.screen.replies.clear()
                self.write(replies)

    def pump(self, wait=0.05):
        """Read once; returns True when output arrived."""
        if self.master is None:
            time.sleep(min(wait, self.remaining()))
            return False
        ready, _, _ = select.select([self.master], [], [], min(wait, self.remaining()))
        if not ready:
            return False
        try:
            block = os.read(self.master, 65536)
        except BlockingIOError:
            return False
        except OSError as exc:
            if exc.errno == errno.EIO:
                return False
            raise
        if block:
            self.take(block)
        return bool(block)

    def drain(self):
        while self.pump(0.03):
            pass

    def write(self, data):
        if self.master is None:
            raise RuntimeError("terminal already hung up")
        view = memoryview(data)
        while view:
            _, ready, _ = select.select([], [self.master], [], min(0.05, self.remaining()))
            if ready:
                try:
                    view = view[os.write(self.master, view):]
                except BlockingIOError:
                    pass
            self.pump(0)

    def cursor_application_mode(self):
        mode = False
        for match in CURSOR_MODE.finditer(self.captured):
            if b"1" in match.group(1).split(b";"):
                mode = match.group(2) == b"h"
        return mode

    def rows(self):
        return [row.rstrip() for row in self.screen.display] if self.screen else None


def leader_exited(pid):
    """True once the leader has exited; it stays a zombie so its group remains identifiable."""
    return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None


def screen_problem(session, spec):
    if session.decoder_error:
        return session.decoder_error
    rows = session.rows()
    if rows is None:
        return "screen assertions need the pyte decoder (python3-pyte), which is not installed"
    for index, pattern in spec.get("rows", {}).items():
        number = int(index)
        if not -len(rows) <= number < len(rows) or not re.search(pattern, rows[number]):
            return "row " + index + " does not match " + repr(pattern)
    for pattern in spec.get("contains", []):
        if not any(re.search(pattern, row) for row in rows):
            return "no row matches " + repr(pattern)
    for pattern in spec.get("lacks", []):
        if any(re.search(pattern, row) for row in rows):
            return "a row matches " + repr(pattern)
    for cell in spec.get("cells", []):
        row, col = cell["row"], cell["col"]
        if not -len(rows) <= row < len(rows) or col >= session.screen.columns:
            return "screen cell " + repr([row, col]) + " is outside the screen"
        char = session.screen.buffer[row % len(rows)][col]
        for name in CELL_FIELDS:
            if name in cell and getattr(char, name) != cell[name]:
                return "cell " + repr([row, col]) + " " + name + " is " + repr(getattr(char, name))
    if "cursor" in spec and [session.screen.cursor.y, session.screen.cursor.x] != spec["cursor"]:
        return "cursor is at " + repr([session.screen.cursor.y, session.screen.cursor.x])
    return None


def termios_problem(fd, spec):
    attrs = termios.tcgetattr(fd)
    for name in spec.get("set", []):
        index, mask = FLAGS[name]
        if attrs[index] & mask != mask:
            return name + " is clear"
    for name in spec.get("clear", []):
        index, mask = FLAGS[name]
        if attrs[index] & mask:
            return name + " is set"
    for name, value in spec.get("cc", {}).items():
        actual = attrs[6][CC[name]]
        actual = actual if isinstance(actual, int) else actual[0]
        if actual != value:
            return name + " is " + str(actual)
    return None


def signal_masks(pid):
    masks = {}
    with open("/proc/%d/status" % pid) as handle:
        for line in handle:
            key, _, value = line.partition(":")
            if key in ("SigIgn", "SigBlk"):
                masks[key] = int(value, 16)
    return masks


def foreground_problem(session, leader, names):
    """None once a job (not the shell) owns the terminal and accepts the signals."""
    group = os.tcgetpgrp(session.master)
    if group == leader:
        return "the shell still owns the terminal"
    members = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            with open("/proc/" + entry + "/stat", "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        fields = data[data.rindex(b")") + 2:].split()
        if int(fields[2]) == group and fields[0] != b"Z":
            members.append(int(entry))
    if not members:
        return "foreground group %d has no live member" % group
    for pid in members:
        try:
            masks = signal_masks(pid)
        except OSError:
            return "process %d vanished" % pid
        for name in names:
            bit = 1 << (getattr(signal, name) - 1)
            for key in ("SigIgn", "SigBlk"):
                if masks.get(key, 0) & bit:
                    return "process %d has %s in %s" % (pid, name, key)
    return None


def wait_for(session, pid, condition, describe):
    """Poll until condition() returns None; a final check follows the leader's exit."""
    while True:
        problem = condition()
        if problem is None:
            return
        if leader_exited(pid):
            session.drain()
            problem = condition()
            if problem is None:
                return
            raise RuntimeError("process exited before " + describe + ": " + problem)
        try:
            session.pump()
        except TimeoutError:
            raise TimeoutError("PTY wall-clock limit waiting for " + describe + ": " + problem)


def execute(argv, env, cwd, case):
    rows, columns = case.get("size", [24, 80])
    timeout = min(case.get("timeout", 12), MAX_TIMEOUT)
    master, slave = pty.openpty()
    os.set_blocking(master, False)
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    # A user's own terminal: owned by the fixture uid, group tty, mode 0620.
    try:
        tty_gid = grp.getgrnam("tty").gr_gid
    except KeyError:
        tty_gid = 5
    root = case.get("privilege") == "root"
    os.fchown(slave, 0 if root else 2000, tty_gid)
    os.fchmod(slave, 0o620)
    initial_modes(slave)
    before = modes(termios.tcgetattr(slave))
    tty_name = os.ttyname(slave)
    set_subreaper()
    session = Session(master, slave, rows, columns, time.monotonic() + timeout,
                      case.get("answer_queries", False))
    events = []
    cursor = 0
    proc = None
    failure = None
    after = None
    strays = []
    harness_error = None
    started = time.monotonic()

    def child():
        os.setsid()
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        child_limits(root=root)

    def event(index, action, **detail):
        events.append(dict(step=index, action=action, t_ms=round((time.monotonic() - started) * 1000),
                           offset=len(session.captured), **detail))

    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=slave, stdout=slave,
                                stderr=slave, preexec_fn=child)
        for index, step in enumerate(case["steps"]):
            (action, value), = step.items()
            if action == "expect":
                pattern = re.compile(value.encode())

                def found():
                    return None if pattern.search(session.captured, cursor) else "not seen"
                wait_for(session, proc.pid, found, "step " + str(index) + " expect " + repr(value))
                cursor = pattern.search(session.captured, cursor).end()
                event(index, action, matched_end=cursor)
            elif action == "output_lacks":
                session.drain()
                hit = re.search(value.encode(), session.captured)
                if hit:
                    raise RuntimeError("step " + str(index) + " output contains " + repr(value) +
                                       " at offset " + str(hit.start()))
                event(index, action)
            elif action in ("send", "send_base64", "key"):
                if action == "send":
                    data = value.encode()
                elif action == "send_base64":
                    data = base64.b64decode(value)
                else:
                    data = KEYS[value][session.cursor_application_mode()]
                session.write(data)
                event(index, action, bytes=len(data))
            elif action == "resize":
                height, width = value
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
                if session.screen:
                    session.screen.resize(lines=height, columns=width)
                event(index, action, size=value)
            elif action == "settle_ms":
                end = time.monotonic() + value / 1000
                while time.monotonic() < end:
                    session.pump(min(0.02, max(end - time.monotonic(), 0)))
                event(index, action)
            elif action == "quiet_ms":
                last = time.monotonic()
                while time.monotonic() - last < value / 1000:
                    if session.pump(0.01):
                        last = time.monotonic()
                event(index, action)
            elif action == "screen":
                try:
                    wait_for(session, proc.pid, lambda: screen_problem(session, value),
                             "step " + str(index) + " screen")
                except (RuntimeError, TimeoutError) as exc:
                    if session.decoder_error or session.screen is None:
                        harness_error = str(exc)  # the decoder, not the program, failed
                    raise
                event(index, action)
            elif action == "termios":
                wait_for(session, proc.pid, lambda: termios_problem(slave, value),
                         "step " + str(index) + " termios")
                event(index, action)
            elif action == "foreground_job":
                wait_for(session, proc.pid, lambda: foreground_problem(session, proc.pid, value),
                         "step " + str(index) + " foreground job")
                event(index, action, group=os.tcgetpgrp(master))
            elif action == "hangup":
                session.drain()
                os.close(master)
                session.master = master = None
                event(index, action)
        while not leader_exited(proc.pid):
            session.pump()
        session.drain()
    except (RuntimeError, TimeoutError, OSError, termios.error) as exc:
        failure = str(exc)
    except Exception as exc:  # a harness defect: keep the evidence, report it as an error
        failure = harness_error = "harness error: %s: %s" % (type(exc).__name__, exc)
    finally:
        try:
            after = modes(termios.tcgetattr(slave))
        except termios.error:
            after = None  # a hung-up terminal cannot be observed any more
        if proc is not None:
            exited = leader_exited(proc.pid)
            # The leader is still unreaped, so its session and group ids cannot
            # have been reused. Everything found belongs to this fixture.
            strays = cleanup(proc.pid)
            if not exited:
                try:
                    os.kill(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            proc.wait()
            strays += cleanup(proc.pid)
        if master is not None:
            os.close(master)
        os.close(slave)
    if strays and failure is None and not case.get("allow_stray_processes", False):
        failure = "processes outlived the session leader: " + ", ".join(
            str(p["pid"]) + ":" + p["name"] for p in strays)
    rendered = session.rows()
    # Shell convention: death by signal N is status 128+N; "signal" keeps N.
    code = proc.returncode if proc else None
    return {"status": None if code is None else code if code >= 0 else 128 - code,
            "signal": -code if code is not None and code < 0 else None,
            "screen_base64": base64.b64encode(bytes(session.captured)).decode(),
            "rendered_screen": rendered,
            "cursor": [session.screen.cursor.y, session.screen.cursor.x] if session.screen else None,
            "decoder": decoder_version(), "decoder_error": session.decoder_error,
            "tty_name": tty_name,
            "terminal_restored": None if after is None else before == after,
            "termios_before": before, "termios_after": after,
            "termios_changes": None if after is None else mode_changes(before, after),
            "stray_processes": strays, "events": events, "error": failure,
            # Set only for harness/decoder defects; "error" still carries it so it never passes.
            "harness_error": harness_error}


def decoder_version():
    if not pyte:
        return None
    try:
        from importlib.metadata import version
        return "pyte " + version("pyte")
    except Exception:
        return "pyte"
