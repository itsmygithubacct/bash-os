#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare tput with ncurses on an explicitly assigned, unused Linux fbcon VT."""
import argparse
import array
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import termios

ACTIVE = Path("/sys/class/tty/tty0/active")
DRM = Path("/sys/class/drm")
SEED = b"TPUT-BASE"
PROBE = "tput-fbcon"
TERMINFO = (
    "tput-fbcon|Linux console with visible initialization strings,\n"
    "\tis1=\\E[2J, is2=\\E[3;5H, is3=INIT,\n"
    "\trs1=\\Ec, rs2=\\E[4;7H, rs3=RESET, use=linux,\n"
)
CANDIDATE = '[[ $EUID == 1000 && $(type -t tput) == builtin ]] || exit 125\nbuiltin tput -T "$1" "$2"'
CC = ("VINTR", "VERASE", "VKILL")
RESET_CC = ("VQUIT", "VEOF", "VSUSP")


def require(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    with open(path, "rb") as fp:
        return hashlib.file_digest(fp, "sha256").hexdigest()


def hardware(vt):
    require(1 <= vt <= 63, "supply a specific VT number from 1 to 63")
    active = ACTIVE.read_text().strip()
    require(active != f"tty{vt}", "requested VT is the foreground console")
    drivers = [entry for entry in Path("/sys/class/vtconsole").glob("vtcon*")
               if "frame buffer" in (entry / "name").read_text() and
               (entry / "bind").read_text().strip() == "1"]
    require(drivers, "no bound framebuffer console")
    fb = next(Path("/dev").glob("fb[0-9]*"), None)
    require(fb is not None, "assign the framebuffer for the requested VT read-only")
    with fb.open("rb", buffering=0) as handle:
        mapping = array.array("I", [vt, 0xffffffff])
        fcntl.ioctl(handle, 0x460f, mapping)  # FBIOGET_CON2FBMAP
    require(fb.name == f"fb{mapping[1]}", "assigned framebuffer differs from VT mapping")
    graphics = Path("/sys/class/graphics") / fb.name
    device = (graphics / "device").resolve(strict=True)
    pci_driver = (device / "driver").resolve(strict=True).name
    require(pci_driver == "i915" and (device / "vendor").read_text().strip() == "0x8086",
            "this hardware fixture requires an Intel display driven by i915")
    connectors = []
    for port in DRM.glob("card*-*"):
        card = DRM / port.name.split("-")[0]
        if ((card / "device").resolve() == device and
                (port / "status").read_text().strip() == "connected" and
                (port / "enabled").read_text().strip() == "enabled"):
            edid = (port / "edid").read_bytes()[:128]
            if len(edid) == 128 and edid.startswith(bytes.fromhex("00ffffffffffff00")) and sum(edid) % 256 == 0:
                connectors.append(port.name)
    require(connectors, "no connected, enabled display on the assigned framebuffer device")
    return dict(vt=vt, foreground=active, framebuffer=fb.name,
                driver=(graphics / "name").read_text().strip(), pci_driver=pci_driver,
                connectors=sorted(connectors), edid_base_checksum_valid=True)


def screen(vcs):
    data = os.pread(vcs, 4 + 2 * 255 * 255, 0)
    require(len(data) >= 4, "missing VCSA header")
    rows, cols, x, y = data[:4]
    require(rows >= 5 and cols >= 20 and len(data) == 4 + 2 * rows * cols,
            "incomplete or undersized VCSA screen")
    chars = data[4::2]
    lines = [chars[i:i+cols].rstrip(b" ").decode("ascii", "backslashreplace")
             for i in range(0, len(chars), cols)]
    return dict(rows=rows, cols=cols, cursor=[x, y], sha256=sha(data),
                text=[[i, text] for i, text in enumerate(lines) if text])


def mode_record(fd):
    settings = termios.tcgetattr(fd)
    return settings[:6] + [[value if isinstance(value, int) else value[0]
                             for value in settings[6]]]


def dirty_modes(fd, original, verb):
    modes = copy.deepcopy(original)
    for name in CC + (RESET_CC if verb == "reset" else ()):
        modes[6][getattr(termios, name)] = b"\0"
    if verb == "reset":
        modes[3] &= ~(termios.ECHO | termios.ICANON)
        modes[1] &= ~termios.ONLCR
    termios.tcsetattr(fd, termios.TCSANOW, modes)


def expected_screen(term, verb):
    if term == PROBE:
        return ([[2, "    INIT"]], [8, 2]) if verb == "init" else ([[3, "      RESET"]], [11, 3])
    return ([[0, SEED.decode()]], [len(SEED), 0]) if verb == "init" else ([], [0, 0])


def check_modes(modes, verb):
    names = CC + (RESET_CC if verb == "reset" else ())
    defaults = [3, 127, 21, 28, 4, 26]
    chars_ok = [modes[6][getattr(termios, name)] for name in names] == defaults[:len(names)]
    flags_ok = (modes[3] & (termios.ECHO | termios.ICANON)) == (termios.ECHO | termios.ICANON)
    return chars_ok and (verb != "reset" or (flags_ok and bool(modes[1] & termios.ONLCR)))


@contextmanager
def assigned_tty(vt):
    fd = os.open(f"/dev/tty{vt}", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
    with os.fdopen(fd, "wb", buffering=0) as tty:
        fcntl.ioctl(fd, termios.TIOCEXCL)
        try:
            yield tty
        finally:
            fcntl.ioctl(fd, termios.TIOCNXCL)


def run(args):
    hw = hardware(args.vt)
    vt = args.vt
    def inactive():
        require(ACTIVE.read_text().strip() == hw["foreground"], "foreground VT changed")

    with open(f"/dev/vcsa{vt}", "rb", buffering=0) as vcs, assigned_tty(vt) as tty:
        fd = tty.fileno()
        for file, major, minor in [(tty, 4, vt), (vcs, 7, 128 + vt)]:
            st = os.fstat(file.fileno())
            require(stat.S_ISCHR(st.st_mode) and st.st_rdev == os.makedev(major, minor),
                    "unexpected device number")
        kdm = array.array("i", [-1])
        fcntl.ioctl(fd, 0x4b3b, kdm)  # KDGETMODE
        require(kdm[0] == 0, "requested VT is not in KD_TEXT mode")
        require(screen(vcs.fileno())["text"] == [], "assigned VT must start blank")
        # The device opener may be root. All trial programs and observers run unprivileged.
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(1000)
            os.setuid(1000)
        require(os.getuid() == os.geteuid() == 1000, "run trials as uid 1000")
        ref = "/usr/bin/tput"
        original = termios.tcgetattr(fd)
        original_modes = mode_record(fd)
        observations = []
        hw.update(tty_rdev=[4, vt], vcsa_rdev=[7, 128 + vt], kd_mode="KD_TEXT",
                  rows=os.get_terminal_size(fd).lines, cols=os.get_terminal_size(fd).columns)
        with tempfile.TemporaryDirectory(prefix="tput-fbcon-") as tmp:
            src = Path(tmp) / "probe.src"
            src.write_text(TERMINFO)
            subprocess.run(["/usr/bin/tic", "-o", tmp, src], check=True)
            env = dict(PATH="/usr/bin:/bin", LC_ALL="C", HOME=tmp, TERMINFO=tmp)
            try:
                for term in ("linux", PROBE):
                    for verb in ("init", "reset"):
                        runs = {}
                        for label, cmd in (
                            ("control", ["/bin/true"]),
                            ("reference", [ref, "-T", term, verb]),
                            ("candidate", [args.shell, "--noprofile", "--norc", "-c",
                                           CANDIDATE, "tput", term, verb]),
                        ):
                            inactive()
                            termios.tcsetattr(fd, termios.TCSANOW, original)
                            os.write(fd, b"\x1bc\x1b[H\x1b[2J" + SEED)
                            termios.tcdrain(fd)
                            dirty_modes(fd, original, verb)
                            before = mode_record(fd)
                            seeded = screen(vcs.fileno())
                            require((seeded["text"], seeded["cursor"]) == expected_screen("linux", "init"),
                                    "could not establish screen control")
                            proc = subprocess.run(cmd, stdin=fd, stdout=fd, stderr=fd,
                                                  env=dict(env, TERM=term), start_new_session=True,
                                                  timeout=8)
                            termios.tcdrain(fd)
                            inactive()
                            runs[label] = dict(status=proc.returncode, before=before, after=mode_record(fd),
                                               screen_before=seeded, screen_after=screen(vcs.fileno()))
                        control, oracle, result = (runs[key] for key in ("control", "reference", "candidate"))
                        end = oracle["screen_after"]
                        controls = (control["status"] == oracle["status"] == 0
                                    and control["before"] == control["after"]
                                    and control["screen_before"] == control["screen_after"]
                                    and control["before"] == oracle["before"]
                                    and oracle["after"] != oracle["before"] and check_modes(oracle["after"], verb)
                                    and (end["text"], end["cursor"]) == expected_screen(term, verb))
                        observations.append(dict(term=term, verb=verb, runs=runs, controls=controls,
                                                 matches=result == oracle))
            finally:
                inactive()
                termios.tcsetattr(fd, termios.TCSANOW, original)
                os.write(fd, b"\x1bc")
                termios.tcdrain(fd)
                inactive()
        restored = mode_record(fd) == original_modes and screen(vcs.fileno())["text"] == []
        require(restored, "could not restore the assigned terminal")
        verdict = "PASS" if all(row["matches"] for row in observations) else "FAIL"
        if not all(row["controls"] for row in observations):
            verdict = "ERROR"
        report = dict(result=verdict, hardware=hw, uid=os.geteuid(), shell_sha256=file_hash(args.shell),
                      reference_sha256=file_hash(ref), linux_terminfo_sha256=file_hash("/usr/share/terminfo/l/linux"),
                      probe_source_sha256=sha(TERMINFO.encode()), restored=restored, observations=observations)
        Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
        print(verdict)
        return {"PASS": 0, "FAIL": 1, "ERROR": 125}[verdict]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vt", required=True, type=int)
    parser.add_argument("--shell", required=True)
    parser.add_argument("--output", required=True)
    try:
        sys.exit(run(parser.parse_args()))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(error, file=sys.stderr)
        sys.exit(125)
