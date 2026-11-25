#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build original launch fixture variants with native macOS tools."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import struct
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().with_name("program.c")
ROOT = SOURCE.parents[2]
VARIANTS = {
    "launch": None,
    "missing-import": "LAUNCH_MISSING_IMPORT",
    "wrong-expectation": "LAUNCH_WRONG_EXPECTATION",
    "exhaust": "LAUNCH_EXHAUST",
}


def capture(*args):
    return subprocess.check_output(args, text=True).strip()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pe_facts(path):
    data = path.read_bytes()
    pe, = struct.unpack_from("<I", data, 0x3C)
    signature, machine, sections = struct.unpack_from("<4sHH", data, pe)
    optional = pe + 24
    magic, = struct.unpack_from("<H", data, optional)
    if (data[:2], signature, machine, magic) != (b"MZ", b"PE\0\0", 0x8664, 0x20B):
        raise ValueError(f"{path.name} is not AMD64 PE32+")
    entry, = struct.unpack_from("<I", data, optional + 16)
    directories = optional + 112
    imports = struct.unpack_from("<II", data, directories + 8)
    relocations = struct.unpack_from("<II", data, directories + 5 * 8)
    optional_size, = struct.unpack_from("<H", data, pe + 20)
    names = [
        data[offset:offset + 8].rstrip(b"\0").decode("ascii")
        for offset in range(optional + optional_size, optional + optional_size + 40 * sections, 40)
    ]
    if not entry or not all(imports):
        raise ValueError(f"{path.name} lacks entry point or imports")
    return {
        "sha256": sha256(path),
        "sections": names,
        "entry_rva": entry,
        "import_directory": imports,
        "relocation_directory": relocations,
    }


def verify_imports(headers, variant):
    _, _, tables = headers.partition("The Import Tables:")
    libraries = re.findall(r"^\s*DLL Name: (\S+)$", tables, re.MULTILINE)
    symbols = re.findall(r"^\s*[0-9]+\s+(\w+)\s*$", tables, re.MULTILINE)
    expected = ["ExitProcess"]
    if variant == "missing-import":
        expected.append("LaunchMissingFixtureImport")
    if libraries != ["kernel32.dll"] or sorted(symbols) != expected:
        raise ValueError(f"{variant}: unexpected imports {libraries}, {symbols}")
    return {"kernel32.dll": sorted(symbols)}



def build_variants(stage, source, clang, link, objdump, compile_flags, link_flags):
    stage.mkdir()
    (stage / "program.c").write_bytes(source)
    variants = {}
    (stage / "kernel32.def").write_text(
        "LIBRARY kernel32.dll\nEXPORTS\n    ExitProcess\n    LaunchMissingFixtureImport\n",
        encoding="ascii",
    )
    subprocess.run(
        [*link, "/lib", "/machine:x64", "/def:kernel32.def", "/out:kernel32.lib"],
        cwd=stage, check=True,
    )
    for name, define in VARIANTS.items():
        extra = [f"-D{define}"] if define else []
        subprocess.run(
            [clang, *compile_flags, *extra, "-c", "program.c", "-o", f"{name}.obj"],
            cwd=stage, check=True,
        )
        subprocess.run(
            [*link, *link_flags, f"/out:{name}.exe", f"{name}.obj", "kernel32.lib"],
            cwd=stage, check=True,
        )
        binary = stage / f"{name}.exe"
        facts = pe_facts(binary)
        if facts["relocation_directory"] != (0, 0):
            raise ValueError(f"{name}: unexpected base relocations")
        headers = subprocess.check_output(
            [objdump, "-p", binary.name], cwd=stage, text=True,
        )
        facts["imports"] = verify_imports(headers, name)
        facts["compile_defines"] = extra
        variants[name] = facts
        (stage / f"{name}.headers.txt").write_text(headers, encoding="utf-8")
    if len({facts["sha256"] for facts in variants.values()}) != len(variants):
        raise ValueError("fixture variants must produce distinct executables")
    return variants


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "launchable-build")
    parser.add_argument(
        "--verify-reproducible", action="store_true",
        help="build twice in separate directories and compare PE hashes and listings",
    )
    options = parser.parse_args()
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("use native ARM64 macOS")
    if capture("/usr/sbin/sysctl", "-n", "sysctl.proc_translated") != "0":
        parser.error("Rosetta is unsupported")

    clang = os.environ.get("CLANG") or capture("/usr/bin/xcrun", "--find", "clang")
    objdump = capture("/usr/bin/xcrun", "--find", "llvm-objdump")
    linker = os.environ.get("LLD_LINK")
    if linker:
        link = [linker]
    else:
        sysroot = Path(capture("rustc", "--print", "sysroot"))
        link = [str(sysroot / "lib/rustlib/aarch64-apple-darwin/bin/rust-lld"), "-flavor", "link"]
    tools = {}
    for name, command in (("clang", [clang]), ("lld", link), ("llvm-objdump", [objdump])):
        tool = command[0]
        if "arm64" not in capture("/usr/bin/lipo", "-archs", tool).split():
            parser.error(f"{name} must have an ARM64 slice: {tool}")
        tools[name] = {
            "version": capture(*command, "--version").splitlines()[0],
            "file": capture("/usr/bin/file", "-bL", tool),
            "libraries": capture("/usr/bin/otool", "-arch", "arm64", "-L", tool).splitlines()[1:],
        }
    output = options.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    compile_flags = [
        "--target=x86_64-pc-windows-msvc", "-O1", "-ffreestanding",
        "-fno-stack-protector", "-Wall", "-Wextra", "-Werror",
    ]
    link_flags = ["/entry:launch_entry", "/subsystem:console", "/nodefaultlib", "/timestamp:0"]
    source = SOURCE.read_bytes()
    receipt = {
        "schema_version": 1,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "tools": tools,
        "compile_flags": compile_flags,
        "link_flags": link_flags,
    }
    with tempfile.TemporaryDirectory(dir=output) as scratch:
        first = Path(scratch) / "first"
        receipt["variants"] = build_variants(first, source, clang, link, objdump, compile_flags, link_flags)
        if options.verify_reproducible:
            second = Path(scratch) / "second"
            variants = build_variants(second, source, clang, link, objdump, compile_flags, link_flags)
            if receipt["variants"] != variants:
                changed = [name for name in VARIANTS if receipt["variants"][name] != variants[name]]
                raise ValueError(f"non-reproducible PE artifacts: {', '.join(changed)}")
            for name in VARIANTS:
                listing = f"{name}.headers.txt"
                if (first / listing).read_bytes() != (second / listing).read_bytes():
                    raise ValueError(f"non-reproducible PE listing: {listing}")
        receipt["reproducibility_verified"] = options.verify_reproducible
        (first / "build.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        for artifact in first.iterdir():
            if artifact.suffix in (".exe", ".txt"):
                artifact.replace(output / artifact.name)
        (first / "build.json").replace(output / "build.json")
    print(f"Built {len(VARIANTS)} source fixtures in {output}")


if __name__ == "__main__":
    main()
