#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare a reference VM, then run parity fixtures in a disposable overlay.

The host runs only QEMU, SSH transport, and artifact handling. No test command
or candidate executable is ever invoked on the host. Test boots have restricted
user networking, no host mounts, and a fresh writable overlay of the sealed base.
"""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import socket
import subprocess
import tarfile
import threading
import time
import urllib.request
import uuid

import schema

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
GUEST_ROOT = "/opt/bashos-parity"
ACCEL = "kvm"  # set from --accel
BOOT_SCALE = 1
REFERENCE_BASH = "/opt/bash-5.3.15"
# Whole-VM limits on the host; the guest itself is 2 vCPU / 2 GiB.
SCOPE_LIMITS = ["CPUQuota=150%", "MemoryMax=3G", "MemorySwapMax=0", "TasksMax=128"]
# QEMU options that would share host state with the guest. Never emitted; the
# guard rejects them in case a later edit introduces one.
FORBIDDEN = ("-virtfs", "-fsdev", "-chardev socket", "smb=", "tftp=", "guestfwd", "vfio",
             "vhost-user", "-usb", "usb-host", "-spice", "-vnc", "-qmp", "-gdb", "bridge",
             "tap,", "-device virtio-9p", "-device vhost", "-device virtio-fs")


def digest(path, algorithm="sha256"):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, algorithm).hexdigest()


def run(argv, **kw):
    return subprocess.run(list(map(str, argv)), check=True, **kw)


def json_write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def fetch(url, path, algorithm, expected):
    if not path.exists():
        temporary = path.with_name(path.name + ".part")
        with urllib.request.urlopen(url, timeout=60) as source, temporary.open("wb") as output:
            shutil.copyfileobj(source, output, 1024 * 1024)
        if digest(temporary, algorithm) != expected:
            temporary.unlink()
            raise RuntimeError("downloaded checksum mismatch: " + url)
        temporary.replace(path)
    if digest(path, algorithm) != expected:
        raise RuntimeError("cached checksum mismatch: " + str(path))
    return path


def image_info(path):
    return json.loads(run(["qemu-img", "info", "--output=json", "--backing-chain", path],
                          capture_output=True).stdout)


def die_with_parent():
    # QEMU runs in its own session; it must not outlive an interrupted controller.
    ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG


def guard_argv(argv, provisioning):
    text = " ".join(argv)
    for option in FORBIDDEN:
        if option in text:
            raise RuntimeError("refusing QEMU option that shares host state: " + option)
    netdevs = [argv[i + 1] for i, word in enumerate(argv) if word == "-netdev"]
    if len(netdevs) != 1 or not netdevs[0].startswith("user,"):
        raise RuntimeError("expected exactly one user-mode network")
    forwards = [item for item in netdevs[0].split(",") if item.startswith("hostfwd=")]
    if len(forwards) != 1 or not forwards[0].startswith("hostfwd=tcp:127.0.0.1:") or not forwards[0].endswith("-:22"):
        raise RuntimeError("only a loopback-bound SSH forward is allowed")
    if not provisioning and "restrict=on" not in netdevs[0].split(","):
        raise RuntimeError("runtime network must be restrict=on")
    if "-nodefaults" not in argv or "spawn=deny" not in text:
        raise RuntimeError("expected -nodefaults and a QEMU sandbox")


class Canary:
    """Loopback listener the guest must not reach while restricted."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(0.5)
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            self.accepted += 1
            connection.close()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
        self.sock.close()


PROBE = r"""
import json, socket, sys
def tcp(host, port):
    try:
        with socket.create_connection((host, port), timeout=4):
            return "connected"
    except OSError as error:
        return "blocked: %s" % (error.strerror or type(error).__name__)
result = {}
try:
    result["dns"] = sorted({a[4][0] for a in socket.getaddrinfo(sys.argv[2], 80, socket.AF_INET, socket.SOCK_STREAM)})
except OSError as error:
    result["dns"] = "blocked: %s" % (error.strerror or type(error).__name__)
result["host_canary"] = tcp("10.0.2.2", int(sys.argv[1]))
public = result["dns"][0] if isinstance(result["dns"], list) else sys.argv[3]
result["public_address"] = public
result["public_tcp"] = tcp(public, 80) if public else "not attempted: no address"
print(json.dumps(result))
"""


class VM:
    POWEROFF_GRACE, TERMINATE_GRACE = 60, 10

    def __init__(self, cache, state, disk, *, provisioning=False):
        self.cache, self.state, self.disk = cache, state, disk
        self.provisioning = provisioning
        self.token = str(uuid.uuid4())
        self.process = None
        self.log = None
        self.lock = None
        self.key = cache / "controller-key"
        self.teardown = {}

    def ssh(self, command, **kw):
        argv = ["ssh", "-F", "/dev/null", "-i", str(self.key), "-p", str(self.port),
                "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ForwardAgent=no",
                "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
                "-o", "ConnectTimeout=3", "-o", "ConnectionAttempts=1",
                "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
                "-o", "StrictHostKeyChecking=accept-new", "-o", "LogLevel=ERROR",
                "-o", "UserKnownHostsFile=" + str(self.state / "known_hosts"),
                "root@127.0.0.1", command]
        return subprocess.run(argv, **kw)

    def argv(self):
        network = (f"user,id=n0,ipv6=off,restrict={'off' if self.provisioning else 'on'},"
                   f"hostfwd=tcp:127.0.0.1:{self.port}-:22")
        argv = ["qemu-system-x86_64", "-nodefaults", "-no-user-config", "-no-reboot",
                "-machine", "q35,accel=" + ACCEL, "-cpu", "host" if ACCEL == "kvm" else "max",
                "-smp", "2", "-m", "2048",
                # Debian trixie's GRUB (gfxterm + serial) resets the guest when no
                # display adapter exists (Debian bug 1111240). An emulated VGA card
                # with no display backend avoids it without editing the image.
                "-device", "VGA", "-display", "none",
                "-d", "guest_errors", "-D", str(self.state / "qemu-debug.log"),
                "-uuid", self.token, "-serial", "stdio", "-monitor", "none",
                "-drive", f"file={self.disk},format=qcow2,if=virtio,cache=writeback",
                "-drive", f"file={self.state / 'seed.iso'},format=raw,media=cdrom,readonly=on",
                "-netdev", network, "-device", "virtio-net-pci,netdev=n0",
                "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
        guard_argv(argv, self.provisioning)
        return argv

    def seed(self):
        public_key = self.key.with_suffix(".pub").read_text().strip()
        seed = self.state / "seed"
        seed.mkdir()
        (seed / "meta-data").write_text(f"instance-id: {self.token}\nlocal-hostname: parity-vm\n")
        (seed / "user-data").write_text(
            "#cloud-config\ndisable_root: false\nssh_pwauth: false\n"
            "package_update: false\npackage_upgrade: false\n"
            "users:\n  - name: root\n    lock_passwd: true\n    ssh_authorized_keys:\n"
            f"      - {public_key}\nwrite_files:\n  - path: /etc/bashos-parity-vm\n"
            "    permissions: '0444'\n    content: |\n"
            f"      {self.token}\n")
        with (self.state / "seed.log").open("wb") as out:
            run(["xorriso", "-as", "mkisofs", "-quiet", "-volid", "cidata", "-joliet", "-rock",
                 "-output", self.state / "seed.iso", seed], stdout=out, stderr=out)

    def __enter__(self):
        # One VM per cache at a time; the lock is released when this process ends.
        self.lock = (self.cache / "vm.lock").open("w")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            raise RuntimeError("another parity VM is using this cache") from None
        try:
            self.state.mkdir(parents=True, exist_ok=False)
            if not self.key.exists():
                run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "parity-vm-ephemeral", "-f", self.key])
            self.seed()
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                self.port = sock.getsockname()[1]
            argv = self.argv()
            scope = ["systemd-run", "--user", "--scope", "--quiet", "--unit", "parity-vm-" + self.token[:8]]
            scope += [item for limit in SCOPE_LIMITS for item in ("-p", limit)]
            json_write(self.state / "vm.json", {"uuid": self.token, "provisioning": self.provisioning,
                       "argv": argv, "scope": scope, "ssh_port": self.port, "started_at": time.time()})
            self.log = (self.state / "console.log").open("wb")
            self.process = subprocess.Popen(["nice", "-n", "10"] + scope + argv, stdin=subprocess.DEVNULL,
                                            stdout=self.log, stderr=subprocess.STDOUT,
                                            start_new_session=True, preexec_fn=die_with_parent)
            deadline = time.monotonic() + 240 * BOOT_SCALE
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError(f"VM stopped during boot (status {self.process.returncode}); inspect console.log")
                try:
                    probe = self.ssh("cat /etc/bashos-parity-vm", capture_output=True, timeout=5)
                except subprocess.TimeoutExpired:
                    continue  # sshd accepted but stalled (e.g. host keys still being generated)
                if probe.returncode == 0 and probe.stdout.decode().strip() == self.token:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("VM boot timed out; inspect console.log")
            result = self.ssh("cloud-init status --wait --long", capture_output=True, timeout=240 * BOOT_SCALE)
            (self.state / "cloud-init.log").write_bytes(result.stdout + result.stderr)
            if result.returncode:
                raise RuntimeError(f"cloud-init did not finish cleanly (status {result.returncode})")
            self.identity = self.verify_identity()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def verify_identity(self):
        script = ("cat /etc/bashos-parity-vm; cat /sys/class/dmi/id/product_uuid; "
                  "systemd-detect-virt --vm; findmnt -J -o TARGET,SOURCE,FSTYPE,OPTIONS; "
                  "ip -j -4 addr show")
        out = self.ssh(script, capture_output=True, timeout=20, check=True).stdout.decode()
        lines = out.split("\n", 3)
        marker, product, virt = (line.strip() for line in lines[:3])
        decoder = json.JSONDecoder()
        mounts, end = decoder.raw_decode(lines[3])
        addresses = decoder.raw_decode(lines[3][end:].lstrip())[0]

        def flatten(nodes):
            for node in nodes:
                yield {key: node.get(key) for key in ("target", "source", "fstype", "options")}
                yield from flatten(node.get("children", []))
        mounts = list(flatten(mounts["filesystems"]))
        shared = [m for m in mounts if m["fstype"] in ("9p", "virtiofs", "nfs", "nfs4", "cifs", "smb3", "fuse.sshfs")]
        identity = {"marker_matches": marker == self.token, "product_uuid_matches": product.lower() == self.token,
                    "virtualization": virt, "host_shared_mounts": shared, "mounts": mounts,
                    "interfaces": {a["ifname"]: [i["local"] for i in a.get("addr_info", [])] for a in addresses}}
        json_write(self.state / "identity.json", identity)
        if not (identity["marker_matches"] and identity["product_uuid_matches"]) or virt not in ("kvm", "qemu") or shared:
            raise RuntimeError("guest identity or isolation check failed; inspect identity.json")
        return identity

    def probe_network(self, public_hint=""):
        canary = Canary()
        try:
            command = shlex.join(["python3", "-I", "-c", PROBE, str(canary.port), "deb.debian.org", public_hint])
            out = self.ssh(command, capture_output=True, timeout=60, check=True).stdout
            result = json.loads(out)
        finally:
            canary.close()
        result["canary_port"], result["canary_accepted"] = canary.port, canary.accepted
        return result

    def stop(self):
        clean = forced = False
        poweroff = None
        if self.process.poll() is None:
            # A hung or unreachable guest must not skip the stop below.
            try:
                poweroff = self.ssh("systemctl poweroff", stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=8).returncode
            except (subprocess.TimeoutExpired, OSError) as error:
                poweroff = type(error).__name__
            try:
                self.process.wait(timeout=self.POWEROFF_GRACE)
                clean = self.process.returncode == 0
            except subprocess.TimeoutExpired:
                forced = True
                self.process.terminate()  # This Popen child only; never a PID search.
                try:
                    self.process.wait(timeout=self.TERMINATE_GRACE)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
        self.teardown = {"qemu_exit_status": self.process.returncode, "clean_poweroff": clean,
                         "forced_stop": forced, "poweroff_request": poweroff, "stopped_at": time.time()}

    def __exit__(self, *ignored):
        try:
            if self.process:
                self.stop()
        finally:
            # Reached even if a second signal interrupts stop(): QEMU never outlives teardown.
            if self.process and self.process.poll() is None:
                self.process.kill()
                self.process.wait()
                self.teardown = {"qemu_exit_status": self.process.returncode, "clean_poweroff": False,
                                 "forced_stop": True, "cleanup_interrupted": True, "stopped_at": time.time()}
            if self.process:
                json_write(self.state / "teardown.json", self.teardown)
            if self.log:
                self.log.close()
            if self.lock:
                self.lock.close()


def provision_script(lock):
    sources = lock["reference_bash"]
    patches = " ".join(shlex.quote(Path(p["url"]).name) for p in sources["patches"])
    return """set -eu
export DEBIAN_FRONTEND=noninteractive
systemctl disable --now apt-daily.timer apt-daily-upgrade.timer
systemctl mask unattended-upgrades.service
apt-get update
apt-get install -y --no-install-recommends """ + " ".join(map(shlex.quote, lock["packages"])) + """
# Reference tools only: their daemons must not run in the sealed base.
for unit in cron.service rsync.service; do
  if systemctl cat "$unit" >/dev/null 2>&1; then systemctl disable --now "$unit"; fi
done
if ! id parity >/dev/null 2>&1; then useradd --uid 2000 --create-home --shell /bin/bash parity; fi
install -d -m 0755 """ + GUEST_ROOT + """
cd /root/bash-src && sha256sum -c --quiet SHA256SUMS
rm -rf build && mkdir build && tar -xzf """ + shlex.quote(Path(sources["url"]).name) + """ -C build
cd build/bash-5.3
for p in """ + patches + """; do patch -p0 -s --no-backup-if-mismatch <../../"$p"; done
./configure --prefix=""" + REFERENCE_BASH + """ >../configure.log 2>&1
make -j2 >../make.log 2>&1
make install >../install.log 2>&1
""" + REFERENCE_BASH + """/bin/bash --version | head -1 >""" + GUEST_ROOT + """/reference-bash.txt
cd / && rm -rf /root/bash-src
dpkg-query -W -f='${Package}\\t${Version}\\n' >""" + GUEST_ROOT + """/packages.tsv
for f in /var/lib/apt/lists/*_InRelease; do printf '%s\\t%s\\n' "${f##*/}" "$(sed -n 's/^Date: //p' "$f")"; done >""" + GUEST_ROOT + """/apt-release.tsv
apt-get clean
rm -f /etc/bashos-parity-vm
cloud-init clean --logs
sync
"""


def prepare(cache, lock):
    base = cache / "prepared.qcow2"
    manifest = cache / "prepared.json"
    if base.exists() or manifest.exists():
        verify_base(cache)
        print("Verified existing prepared VM.", flush=True)
        return
    original = fetch(lock["url"], cache / "debian.qcow2", "sha512", lock["sha512"])
    sources = cache / "bash-src"
    sources.mkdir(exist_ok=True)
    spec = lock["reference_bash"]
    for item in [spec] + spec["patches"]:
        fetch(item["url"], sources / Path(item["url"]).name, "sha256", item["sha256"])
    (sources / "SHA256SUMS").write_text("".join(f"{i['sha256']}  {Path(i['url']).name}\n"
                                                for i in [spec] + spec["patches"]))
    disk = cache / "provisioning.qcow2"
    state = cache / ("provision-" + str(uuid.uuid4()))
    if disk.exists():
        # Scratch left by an interrupted run: keep it for diagnosis, never reuse it.
        stale = cache / ("stale-" + str(uuid.uuid4()))
        stale.mkdir()
        disk.rename(stale / disk.name)
    run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", original, disk, "12G"])
    try:
        with VM(cache, state, disk, provisioning=True) as vm:
            # Positive control: the probe must see the canary and the mirror while unrestricted.
            control = vm.probe_network()
            json_write(state / "network-control.json", control)
            if control["host_canary"] != "connected" or control["public_tcp"] != "connected" or not control["canary_accepted"]:
                raise RuntimeError("network probe positive control failed; inspect network-control.json")
            with tarfile.open(state / "bash-src.tar", "w") as archive:
                archive.add(sources, arcname="bash-src")
            with (state / "bash-src.tar").open("rb") as stream:
                vm.ssh("rm -rf /root/bash-src && tar -xf - -C /root", stdin=stream, check=True, timeout=60)
            with (state / "provision.log").open("wb") as out:
                result = vm.ssh("/bin/bash -se", input=provision_script(lock).encode(), stdout=out,
                                stderr=subprocess.STDOUT, timeout=1800)
            if result.returncode:
                raise RuntimeError("reference provisioning failed; inspect provision.log")
            facts = vm.ssh(f"cat {GUEST_ROOT}/packages.tsv; echo '#'; cat {GUEST_ROOT}/apt-release.tsv; "
                           f"echo '#'; cat {GUEST_ROOT}/reference-bash.txt; echo '#'; uname -r; "
                           "/bin/bash --version | head -1",
                           capture_output=True, check=True, timeout=10).stdout.decode()
        if not vm.teardown.get("clean_poweroff"):
            raise RuntimeError("provisioning VM did not power off cleanly; refusing to seal")
        packages, releases, bash53, rest = facts.split("#\n")
        kernel, system_bash = rest.strip().splitlines()
        # Flatten the base: later runs do not depend on a mutable backing chain.
        partial = cache / "prepared.part"
        run(["qemu-img", "convert", "-f", "qcow2", "-O", "qcow2", disk, partial])
        partial.chmod(0o444)
        partial.replace(base)
    except BaseException:
        # Keep the failed scratch disk with its logs; a retry starts from a new overlay.
        if disk.exists() and state.exists():
            disk.rename(state / "provisioning-failed.qcow2")
        raise
    json_write(manifest, {"schema": 2, "sha256": digest(base),
               "base_image_sha512": lock["sha512"], "image_lock_sha256": digest(HERE / "image.lock.json"),
               "qemu": run(["qemu-system-x86_64", "--version"], capture_output=True, text=True).stdout.splitlines()[0],
               "guest_kernel": kernel, "system_bash": system_bash, "reference_bash": bash53.strip(),
               "reference_bash_path": REFERENCE_BASH + "/bin/bash",
               "packages": dict(line.split("\t", 1) for line in packages.splitlines()),
               "apt_release_dates": dict(line.split("\t", 1) for line in releases.splitlines()),
               "network_control": control, "provisioning_state": state.name,
               "provisioned_at": time.time()})
    manifest.chmod(0o444)
    disk.unlink()
    print("Prepared and sealed disposable reference VM.", flush=True)


def verify_base(cache):
    # Always rehash: a stored manifest is a claim, not evidence.
    info = json.loads((cache / "prepared.json").read_text())
    if info["image_lock_sha256"] != digest(HERE / "image.lock.json"):
        raise RuntimeError("image/package specification changed; use a fresh cache")
    if info["sha256"] != digest(cache / "prepared.qcow2"):
        raise RuntimeError("prepared image checksum mismatch")
    chain = image_info(cache / "prepared.qcow2")
    if len(chain) != 1 or "backing-filename" in chain[0]:
        raise RuntimeError("prepared image must be flattened")
    return info


def payload(binary, output, reference_cache):
    ledger = HERE / "deferrals.json"
    if ledger.exists():
        import deferrals
        deferrals.validate(json.loads(ledger.read_text()), REPO)
    # Explicit input roots; never archive the repository's .git, home, or keys.
    def metadata(info):
        if not info.isfile():
            raise ValueError("payload inputs must be regular files: " + info.name)
        # Source worktrees can be private (0600). The guest's unprivileged
        # historical runner must be able to read these synthetic inputs.
        info.mode = 0o755 if info.name == "candidate" else 0o644
        info.uid = info.gid = info.mtime = 0
        info.uname = info.gname = ""
        return info

    with tarfile.open(output, "w") as archive:
        archive.add(binary, arcname="candidate", recursive=False, filter=metadata)
        for root, prefix in [(HERE, "harness"), (REPO / "tests/loadable-parity", "loadable-parity")]:
            for path in sorted(root.rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts:
                    archive.add(path, arcname=prefix + "/" + str(path.relative_to(root)), recursive=False, filter=metadata)
        if reference_cache:
            for path in sorted(reference_cache.iterdir()):
                if path.is_file():
                    archive.add(path, arcname="reference-data/" + path.name, recursive=False, filter=metadata)


def evaluate(args, cache):
    info = verify_base(cache)
    base = cache / "prepared.qcow2"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    check = args.operation == "check"
    binary = None if check else args.binary.resolve(strict=True)
    before = None if check else digest(binary)
    disk = output / "overlay.qcow2"
    record = {"operation": args.operation, "status": "error", "candidate_sha256": before, "prepared_sha256": info["sha256"],
              "image_lock_sha256": info["image_lock_sha256"], "groups": [g for g in args.groups.split(",") if g],
              "packages": info["packages"], "reference_bash": info.get("reference_bash"),
              "system_bash": info.get("system_bash"), "host_mounts": []}
    record["selected_case_ids"] = sorted(args.case_ids.split(",")) if not check and args.case_ids is not None else None
    record["accelerator"] = ACCEL
    record["root_fixtures_allowed"] = bool(getattr(args, "allow_root_fixtures", False))
    record["runtime_host"] = {"kernel": platform.release(), "architecture": platform.machine(),
                              "qemu": run(["qemu-system-x86_64", "--version"], capture_output=True,
                                          text=True).stdout.splitlines()[0],
                              "limits": SCOPE_LIMITS}
    result_code = 2
    vm = None
    try:
        run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base, disk])
        chain = image_info(disk)
        if len(chain) != 2 or Path(chain[0]["full-backing-filename"]) != base:
            raise RuntimeError("overlay backing chain is not the sealed base")
        if not check:
            payload(binary, output / "payload.tar", args.references)
            record["payload_sha256"] = digest(output / "payload.tar")
        vm = VM(cache, output / "vm", disk)
        with vm:
            record["vm_uuid"], record["identity"] = vm.token, vm.identity
            # Isolation must be shown before the candidate leaves the host.
            network = vm.probe_network(info.get("network_control", {}).get("public_address", ""))
            record["runtime_network"] = network
            if network["host_canary"] == "connected" or network["public_tcp"] == "connected" \
                    or network["canary_accepted"] or isinstance(network["dns"], list):
                raise RuntimeError("runtime guest reached the host or the internet; candidate not uploaded")
            if check:
                # Lifecycle check only: trusted guest tools, no candidate, no fixtures.
                facts = vm.ssh("unshare --net ip -j link show; echo; "
                               f"{REFERENCE_BASH}/bin/bash --version | head -1; /bin/bash --version | head -1; "
                               f"test ! -e {GUEST_ROOT}/candidate && test ! -e {GUEST_ROOT}/results && echo clean",
                               capture_output=True, check=True, timeout=20).stdout.decode().splitlines()
                record["fixture_namespace_links"] = [link["ifname"] for link in json.loads(facts[0])]
                record["guest_reference_bash"], record["guest_system_bash"] = facts[2], facts[3]
                record["guest_opt_clean"] = facts[4:] == ["clean"]
                if record["fixture_namespace_links"] != ["lo"] or not record["guest_opt_clean"]:
                    raise RuntimeError("fixture namespace or guest state check failed")
                record["status"], result_code = "checked", 0
                return result_code
            with (output / "payload.tar").open("rb") as stream:
                uploaded = vm.ssh(f"tee {GUEST_ROOT}/payload.tar | sha256sum", stdin=stream, capture_output=True,
                                  check=True, timeout=60).stdout.decode().split()[0]
            if uploaded != record["payload_sha256"]:
                raise RuntimeError("payload hash mismatch after upload")
            vm.ssh(f"tar -xf {GUEST_ROOT}/payload.tar -C {GUEST_ROOT} --no-same-owner && "
                   f"rm {GUEST_ROOT}/payload.tar && chmod 755 {GUEST_ROOT}/candidate", check=True, timeout=60)
            command = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--unit=parity-evaluation",
                       "-p", "MemoryMax=1200M", "-p", "MemorySwapMax=0", "-p", "TasksMax=128",
                       "-p", "RuntimeMaxSec=1800", "-p", "KillMode=control-group",
                       "unshare", "--mount", "--pid", "--fork", "--net", "--mount-proc", "--kill-child",
                       "/usr/bin/python3", f"{GUEST_ROOT}/harness/guest.py", "--vm-token", vm.token,
                       "--groups", args.groups]
            if args.case_ids is not None:
                command += ["--case-ids", args.case_ids]
            if args.allow_root_fixtures:
                command.append("--allow-root-fixtures")
            with (output / "run.log").open("wb") as log:
                evaluation = vm.ssh(shlex.join(command), stdout=log, stderr=subprocess.STDOUT, timeout=1900)
            result_code = record["guest_exit_status"] = evaluation.returncode
            # Evidence is data. Keep the tarball without extracting guest-controlled paths on the host.
            with (output / "evidence.tar").open("wb") as archive:
                vm.ssh(f"tar -cf - -C {GUEST_ROOT} results", stdout=archive, check=True, timeout=120)
            data = vm.ssh(f"cat {GUEST_ROOT}/results/summary.json", capture_output=True, check=True, timeout=10).stdout
            report = json.loads(data)
            record["candidate_matches_guest"] = report.get("binary_sha256") == record["candidate_sha256"]
            if not record["candidate_matches_guest"]:
                raise RuntimeError("guest report does not identify the uploaded candidate")
            json_write(output / "summary.json", report)
        record["status"] = "completed"
        print(json.dumps(report["summary"], sort_keys=True), flush=True)
    except BaseException as error:
        record["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        record["teardown"] = vm.teardown if vm else {}
        record["candidate_unchanged"] = check or before == digest(binary)
        if not args.keep_overlay:
            disk.unlink(missing_ok=True)
        record["overlay_discarded"] = not disk.exists()
        record["prepared_unchanged"] = digest(base) == info["sha256"]
        json_write(output / "provenance.json", record)
        if record["status"] == "completed" and not (record["candidate_unchanged"] and record["prepared_unchanged"]):
            raise RuntimeError("candidate or sealed base changed during evaluation")
    return result_code


def interrupt(signum, frame):
    raise KeyboardInterrupt(f"signal {signum}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True, help="private directory outside the checkout")
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("prepare")
    sub.add_parser("check", help="boot a disposable runtime VM and verify isolation without a candidate").add_argument(
        "--output", type=Path, required=True)
    test = sub.add_parser("run")
    test.add_argument("--binary", type=Path, required=True)
    test.add_argument("--output", type=Path, required=True)
    test.add_argument("--references", type=Path)
    test.add_argument("--groups", default="terminal,network,reference,shell")
    test.add_argument("--case-ids", help="comma-separated modern fixture IDs for a bounded batch")
    test.add_argument("--keep-overlay", action="store_true", help="retain disposable disk for diagnosis")
    test.add_argument("--allow-root-fixtures", action="store_true",
                      help="run privilege=root fixtures as uid 0 in the guest; for rented hosts only")
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm",
                        help="tcg emulates the guest CPU where the host has no usable /dev/kvm")
    args = parser.parse_args()
    global ACCEL, BOOT_SCALE
    ACCEL, BOOT_SCALE = args.accel, 1 if args.accel == "kvm" else 6
    if args.operation == "check":
        args.groups, args.keep_overlay = "", False
    if args.operation == "run":
        groups = set(args.groups.split(","))
        if not groups or groups - schema.GROUPS:
            parser.error("unknown groups: " + ",".join(sorted(groups - schema.GROUPS)))
        if args.case_ids is not None:
            cases, _ = schema.load(HERE / "suites")
            selected = schema.select(cases, groups, set(args.case_ids.split(",")))
            if any(case.get("privilege") == "root" for case in selected) and not args.allow_root_fixtures:
                parser.error("root fixtures selected; pass --allow-root-fixtures (rented hosts only)")
    cache = args.cache.resolve()
    if cache == REPO or REPO in cache.parents:
        parser.error("VM images and ephemeral credentials must live outside the checkout")
    cache.mkdir(parents=True, exist_ok=True, mode=0o700)
    # QEMU's key=value parsers treat commas specially; reject ambiguous paths.
    if "," in str(cache) or (hasattr(args, "output") and "," in str(args.output.resolve())):
        parser.error("QEMU storage paths must not contain commas")
    if args.accel == "kvm" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        parser.error("usable /dev/kvm is required (or --accel tcg); no host-execution fallback")
    for tool in ("qemu-system-x86_64", "qemu-img", "xorriso", "ssh", "ssh-keygen", "systemd-run"):
        if not shutil.which(tool):
            parser.error("missing host tool: " + tool)
    # Turn termination into an exception so the VM is shut down and evidence written.
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    lock = json.loads((HERE / "image.lock.json").read_text())
    if args.operation == "prepare":
        prepare(cache, lock)
        return 0
    return evaluate(args, cache)


if __name__ == "__main__":
    raise SystemExit(main())
