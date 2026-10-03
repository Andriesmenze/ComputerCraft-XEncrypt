-- Runs tests/ingame_selftest.lua in the emulator, so the in-game script itself
-- is known to work before anyone copies it to a CC computer.

test("in-game self-test passes in the emulator", function()
    local C = cc.newComputer(1)
    C:runProgram("tests/ingame_selftest.lua")
    local text = table.concat(C.output, "\n")
    ok(text:find("xEncrypt 1.0 self-test", 1, true), text)
    ok(text:find("\n9 passed, 0 failed", 1, true), text)
    ok(text:find("hashPassword:", 1, true), text)
end)
