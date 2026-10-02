-- Checks on the files that go onto CC computers.

-- Before CC:Tweaked 1.109 source files were read through a UTF-8 decoder, so a
-- non-ASCII byte in a file could load differently depending on the version.
local IN_GAME_FILES = { "apis/xEncrypt.lua", "apis/Unicode.lua", "tests/ingame_selftest.lua" }

for _, path in ipairs(IN_GAME_FILES) do
    test(path .. " is pure ASCII", function()
        local fh = assert(io.open(cc.root .. "/" .. path, "rb"))
        local src = fh:read("*a")
        fh:close()
        local line = 1
        for i = 1, #src do
            local b = src:byte(i)
            if b == 10 then line = line + 1 end
            if b > 127 then error("non-ASCII byte " .. b .. " on line " .. line, 0) end
        end
    end)
end
