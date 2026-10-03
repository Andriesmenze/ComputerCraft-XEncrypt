#!/usr/bin/env python3
"""Run tests/ingame_selftest.lua on CraftOS-PC, which ships the real CC:Tweaked ROM.

    python tests/run_craftos.py

CraftOS-PC: https://www.craftos-pc.cc. Set CRAFTOS_PC to CraftOS-PC_console.exe
if it is not in C:\\Program Files\\CraftOS-PC\\. Work files go to the system temp folder.
"""
import os
import shutil
import subprocess
import sys
import tempfile

EXE = os.environ.get("CRAFTOS_PC", r"C:\Program Files\CraftOS-PC\CraftOS-PC_console.exe")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STARTUP = r"""
-- CraftOS-PC adds os.epoch("nano"); CC:Tweaked raises an error for it.
local epoch = os.epoch
os.epoch = function(kind)
    if type(kind) == "string" and kind:lower() == "nano" then error("Unsupported operation", 2) end
    return epoch(kind)
end
local log = fs.open("/selftest.log", "w")
local function capture(prefix, ...)
    local t = {}
    for i = 1, select("#", ...) do t[i] = tostring((select(i, ...))) end
    log.writeLine(prefix .. table.concat(t, "\t"))
    log.flush()
end
local realPrint, realPrintError = print, printError
_G.print = function(...) capture("", ...) return realPrint(...) end
_G.printError = function(...) capture("ERROR ", ...) return realPrintError(...) end
capture("host: ", _HOST)
local ok = shell.run("/tests/ingame_selftest.lua")
capture("DONE ", tostring(ok))
log.close()
os.shutdown()
"""


def main():
    sys.stdout.reconfigure(errors="backslashreplace")
    if not os.path.exists(EXE):
        print(f"CraftOS-PC not found at {EXE} (set CRAFTOS_PC)")
        return 2
    data = tempfile.mkdtemp(prefix="xencrypt-craftos-")
    computer = os.path.join(data, "computer", "0")
    shutil.copytree(os.path.join(ROOT, "apis"), os.path.join(computer, "apis"))
    os.makedirs(os.path.join(computer, "tests"))
    shutil.copyfile(os.path.join(ROOT, "tests", "ingame_selftest.lua"), os.path.join(computer, "tests", "ingame_selftest.lua"))
    with open(os.path.join(computer, "startup.lua"), "w", newline="\n") as f:
        f.write(STARTUP)
    try:
        subprocess.run([EXE, "--headless", "-d", data, "--id", "0"], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=120)
    except subprocess.TimeoutExpired:
        print("CraftOS-PC did not exit within 120 s")
        return 1
    log_path = os.path.join(computer, "selftest.log")
    log = open(log_path, encoding="utf-8", errors="replace").read() if os.path.exists(log_path) else ""
    print(log.rstrip() or "(no output)")
    shutil.rmtree(data, ignore_errors=True)
    passed = "DONE true" in log and ", 0 failed" in log and "ERROR" not in log
    print("craftos   ingame_selftest.lua      " + ("ok" if passed else "FAILED"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
