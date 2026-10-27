#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Collect reference interfaces in the VM; help is metadata, never parity proof."""
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess


def evaluate(root, output):
    import guest
    guest.require_guest(Path("/etc/bashos-parity-vm").read_text().strip())
    directory = output / "inventory"
    directory.mkdir()
    working = guest.workspace({})

    def execute(argv):
        return guest.plain(argv, guest.environment("reference"), working,
                           {"timeout": 3, "output_limit": 1024 * 1024})

    def text(result):
        return base64.b64decode(result["stdout_base64"]).decode(errors="replace")

    metadata = {}
    names = {}
    for label, shell in (("candidate", root / "candidate"), ("reference", guest.REFERENCE_SHELL)):
        result = execute([str(shell), "--noprofile", "--norc", "-c", "builtin compgen -b"])
        if result["error"] or result["status"]:
            raise RuntimeError(label + " builtin inventory failed")
        names[label] = sorted(set(text(result).splitlines()))
        metadata[label] = {"names": names[label], "sha256": hashlib.sha256(shell.read_bytes()).hexdigest(),
                           "set": execute([str(shell), "--noprofile", "--norc", "-c", "set -o"]),
                           "shopt": execute([str(shell), "--noprofile", "--norc", "-c", "shopt -p"]),
                           "invocation": execute([str(shell), "--help"])}
    files = subprocess.check_output(["dpkg-query", "-L", "coreutils"], text=True).splitlines()
    coreutils = sorted({Path(p).name for p in files if Path(p).parent.as_posix() in ("/usr/bin", "/bin", "/usr/sbin", "/sbin")})
    commands = []
    for name in sorted(set(names["candidate"]) | set(coreutils)):
        item = {"name": name, "candidate_builtin": name in names["candidate"],
                "reference_builtin": name in names["reference"], "gnu_coreutils": name in coreutils}
        for label, shell in (("candidate", root / "candidate"), ("reference", guest.REFERENCE_SHELL)):
            if name in names[label]:
                result = execute([str(shell), "--noprofile", "--norc", "-c", 'help -s "$1"', "inventory", name])
                item[label + "_help"] = result
        external = shutil.which(name, path="/usr/bin:/bin:/usr/sbin:/sbin")
        item["reference_external"] = external
        # GNU Coreutils has a documented --help interface. Other tools' flags
        # need an explicit mapping; never guess an option for a daemon/device tool.
        if name in coreutils and external:
            result = execute([external, "--help"])
            item["gnu_help"] = result
            item["reference_option_tokens"] = sorted(set(re.findall(r"(?<!\w)--[A-Za-z][A-Za-z0-9-]*|(?<!\w)-[A-Za-z0-9](?!\w)", text(result))))
            item["reference_option_status"] = "help-derived tokens; argument grammar/interactions require manual review"
        item["parity_status"] = "NOT_ASSESSED_BY_METADATA"
        commands.append(item)
    packages = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], text=True)
    report = {"schema": 1, "shells": metadata, "commands": commands,
              "packages": dict(line.split("\t", 1) for line in packages.splitlines()),
              "coreutils_without_candidate_builtin": sorted(set(coreutils) - set(names["candidate"])),
              "claim": "interface inventory only; options/help listing never discharges behavior coverage"}
    guest.write_json(directory / "interfaces.json", report)
    return [{"id": "inventory-collected", "group": "inventory", "kind": "metadata", "status": "COLLECTED",
             "comparison": "metadata collection only", "commands": len(commands),
             "coreutils_commands": len(coreutils),
             "coreutils_without_candidate_builtin": report["coreutils_without_candidate_builtin"]}]
