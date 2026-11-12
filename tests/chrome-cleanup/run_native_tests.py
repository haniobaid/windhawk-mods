"""Build and run the exact submitted modules using native Windows APIs.

This runner never launches Chrome and never touches its real policy keys. The
test process redirects HKCU and HKLM to separate disposable application hives.
Actual Windhawk injection, Chrome cache/exit behavior, and login retention remain
separate interactive integration checks.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys


def extract(source: str, name: str) -> str:
    begin = f"// BEGIN_{name}"
    end = f"// END_{name}"
    if source.count(begin) != 1 or source.count(end) != 1:
        raise RuntimeError(f"Expected exactly one pair of {name} markers")
    return source.split(begin, 1)[1].split(end, 1)[0].strip() + "\n"


def run(arguments: list[str], **kwargs) -> None:
    print("Running:", subprocess.list2cmdline([str(x) for x in arguments]), flush=True)
    subprocess.run(arguments, check=True, **kwargs)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--windhawk-dir", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if sys.platform != "win32":
        raise RuntimeError("These are native Windows tests, not a Linux simulation")
    compiler = args.windhawk_dir / "Compiler" / "bin" / "clang++.exe"
    if not compiler.is_file():
        raise RuntimeError(f"Windhawk compiler missing: {compiler}")
    args.output.mkdir(parents=True, exist_ok=True)
    source_bytes = args.source.read_bytes()
    print("Checked-out source SHA256:", hashlib.sha256(source_bytes).hexdigest())
    source = source_bytes.decode("utf-8").replace("\r\n", "\n")
    print("Submitted source SHA256 (normalized LF):",
          hashlib.sha256(source.encode("utf-8")).hexdigest())
    modules = {
        "TRANSIENT_POLICY_OVERLAY": "policy_overlay.inc",
        "KEEP_SITE_SETTINGS": "mod_settings.inc",
        "POLICY_REFRESH": "policy_refresh.inc",
    }
    for marker, name in modules.items():
        code = extract(source, marker)
        path = args.output / name
        path.write_text(code, encoding="utf-8", newline="\n")
        print(name, "SHA256:", hashlib.sha256(path.read_bytes()).hexdigest())
    harness = Path(__file__).with_name("native_policy_tests.cpp")
    if not harness.is_file():
        raise RuntimeError("Native behavior harness missing")
    shutil.copyfile(harness, args.output / harness.name)
    executable = args.output / "native_policy_tests.exe"
    run([
        str(compiler), "-std=c++23", "-O0", "-g", "-Wall", "-Wextra", "-Werror",
        "-DUNICODE", "-D_UNICODE", "-DWINVER=0x0A00", "-D_WIN32_WINNT=0x0A00",
        "-D_WIN32_IE=0x0A00", "-DNTDDI_VERSION=0x0A000008",
        "-target", "x86_64-w64-mingw32", "-static",
        str(args.output / harness.name), "-o", str(executable),
        "-ladvapi32", "-lole32", "-lshell32", "-luserenv",
    ])
    env = dict(os.environ)
    env["PATH"] = str(compiler.parent) + os.pathsep + env.get("PATH", "")
    run([str(executable)], env=env, timeout=90)
    classifier_cases = [
        ("browser", []),
        ("child", ["--type=renderer"]),
        ("child", ["--TYPE=utility"]),
        ("child", ["/type=gpu-process"]),
        ("child", [" --type=renderer "]),
        ("browser", ["--", "--type=renderer"]),
        ("browser", ["--single-argument", "--type=renderer"]),
    ]
    for expected, arguments in classifier_cases:
        run([str(executable), "--classifier-only", expected, *arguments],
            env=env, timeout=15)
    print("PASS native API/behavior tests and Windows command-line classification.")
    print("Not exercised: actual Windhawk injection, Chrome policy consumption, "
          "Chrome exit cleanup, or preserved website login.")


if __name__ == "__main__":
    main()
