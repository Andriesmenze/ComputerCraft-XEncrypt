#!/usr/bin/env python3
"""Run the Lua test suites in tests/ on the Lua runtimes bundled with lupa.

    pip install lupa
    python tests/run_tests.py                 # every runtime, every test file
    python tests/run_tests.py --lua lua52     # only Lua 5.2 (closest to CC:Tweaked)
    python tests/run_tests.py -k xEncrypt     # only test files whose name contains "xEncrypt"
    python tests/run_tests.py --heavy         # include slow tests (long PBKDF2 runs etc.)

CC:Tweaked runs Lua 5.2 semantics with bit32 (Cobalt), so lua52 is the reference
runtime; the others check that nothing depends on version-specific behaviour.
"""
import argparse
import glob
import importlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import reference  # noqa: E402  (differential tests against Python implementations)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
RUNTIMES = ["lua52", "lua51", "lua53", "lua54", "luajit21"]

BOOT = r"""
local root, testFile, heavy = ...
local cc = dofile(root .. "/tests/cc_env.lua")
cc.root = root
cc.heavy = heavy
local T = dofile(root .. "/tests/testlib.lua")
T.cc = cc
_G.cc, _G.T = cc, T
dofile(testFile)
return T.summary()
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lua", default=",".join(RUNTIMES), help="comma separated lupa runtimes")
    parser.add_argument("-k", default="", help="only run test files whose name contains this")
    parser.add_argument("--heavy", action="store_true", help="include slow tests")
    args = parser.parse_args()

    files = sorted(f.replace("\\", "/") for f in glob.glob(os.path.join(ROOT, "tests", "test_*.lua")))
    files = [f for f in files if args.k in os.path.basename(f)]
    if not files and args.k not in "reference.py":
        print("no test files found")
        return 1

    total_failed = 0
    for name in [r.strip() for r in args.lua.split(",") if r.strip()]:
        try:
            module = importlib.import_module("lupa." + name)
        except ImportError:
            print(f"{name}: not available in this lupa build, skipped")
            continue
        for path in files:
            runtime = module.LuaRuntime(unpack_returned_tuples=True, encoding=None)
            started = time.time()
            try:
                passed, failed, skipped, failures = runtime.execute(BOOT, ROOT.encode(), path.encode(), args.heavy)
                failures = failures.decode("utf-8", "replace")
            except Exception as exc:  # the test file itself failed to load or run
                passed, failed, skipped, failures = 0, 1, 0, f"{type(exc).__name__}: {exc}"
            elapsed = time.time() - started
            status = "ok" if failed == 0 else "FAILED"
            print(f"{name:9} {os.path.basename(path):24} {status:6} {passed} passed, {failed} failed, "
                  f"{skipped} skipped ({elapsed:.1f}s)")
            if failed:
                print("    " + str(failures).replace("\n", "\n    "))
            total_failed += failed
        if args.k in "reference.py":
            started = time.time()
            try:
                passed, failed, skipped, failures = reference.run(module, ROOT)
            except Exception as exc:
                passed, failed, skipped, failures = 0, 1, 0, f"{type(exc).__name__}: {exc}"
            status = "ok" if failed == 0 else "FAILED"
            print(f"{name:9} {'reference.py':24} {status:6} {passed} passed, {failed} failed, "
                  f"{skipped} skipped ({time.time() - started:.1f}s)")
            if failed:
                print("    " + str(failures).replace("\n", "\n    "))
            total_failed += failed
    return 1 if total_failed else 0


if __name__ == "__main__":
    sys.exit(main())
