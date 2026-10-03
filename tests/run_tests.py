#!/usr/bin/env python3
"""Run the Lua test suites in tests/ on the Lua runtimes bundled with lupa.

    pip install lupa
    python tests/run_tests.py                 # every runtime, every test file
    python tests/run_tests.py --lua lua52     # only Lua 5.2 (closest to CC:Tweaked)
    python tests/run_tests.py -k xEncrypt     # only test files whose name contains "xEncrypt"
    python tests/run_tests.py --heavy         # include slow tests (long PBKDF2 runs etc.)

CC:Tweaked runs Lua 5.2 semantics with bit32 (Cobalt), so lua52 is the reference
runtime; the others check that nothing depends on version-specific behaviour.
`pip install cryptography` adds the comparisons with OpenSSL (they are reported
as skipped without it).
"""
import argparse
import glob
import importlib
import importlib.util
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__))).replace("\\", "/")
RUNTIMES = ["lua52", "lua51", "lua53", "lua54", "luajit21"]

# A test file that runs longer than the time limit (in CPU seconds) fails
# instead of hanging the runner.
BOOT = r"""
local root, testFile, heavy, timeLimit = ...
local deadline = os.clock() + timeLimit
debug.sethook(function()
    if os.clock() > deadline then
        error("timeout: the test file ran longer than " .. timeLimit .. " s", 2)
    end
end, "", 1000000)
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
    # Keep failure text printable when the output is piped (cp1252 on Windows).
    sys.stdout.reconfigure(errors="backslashreplace")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lua", help="comma separated lupa runtimes (default: all that are available)")
    parser.add_argument("-k", default="", help="only run test files whose name contains this")
    parser.add_argument("--heavy", action="store_true", help="include slow tests")
    parser.add_argument("--timeout", type=float, default=600, help="CPU seconds allowed per test file")
    args = parser.parse_args()

    if importlib.util.find_spec("lupa") is None:
        print("lupa is not installed (pip install lupa)")
        return 2
    import reference  # differential tests against Python implementations

    files = sorted(f.replace("\\", "/") for f in glob.glob(os.path.join(ROOT, "tests", "test_*.lua")))
    files = [f for f in files if args.k in os.path.basename(f)]
    if not files and args.k not in "reference.py":
        print("no test files found")
        return 1

    explicit = args.lua is not None
    names = [r.strip() for r in (args.lua or ",".join(RUNTIMES)).split(",") if r.strip()]
    total_failed, ran = 0, 0
    for name in names:
        try:
            module = importlib.import_module("lupa." + name)
        except ImportError:
            print(f"{name}: not available in this lupa build" + ("" if explicit else ", skipped"))
            total_failed += 1 if explicit else 0
            continue
        ran += 1
        for path in files:
            runtime = module.LuaRuntime(unpack_returned_tuples=True, encoding=None)
            started = time.time()
            try:
                passed, failed, skipped, failures = runtime.execute(
                    BOOT, ROOT.encode(), path.encode(), args.heavy, args.timeout)
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
    if ran == 0:
        print("no Lua runtime ran")
        return 1
    return 1 if total_failed else 0


if __name__ == "__main__":
    sys.exit(main())
