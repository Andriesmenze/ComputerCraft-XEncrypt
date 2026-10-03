-- Checks on the files that go onto CC computers.

local IN_GAME_FILES = { "apis/xEncrypt.lua", "apis/Unicode.lua", "tests/ingame_selftest.lua" }

local function read(path)
    local fh = assert(io.open(cc.root .. "/" .. path, "rb"))
    local src = fh:read("*a")
    fh:close()
    return src
end

-- Before CC:Tweaked 1.109 source files were read through a UTF-8 decoder, so a
-- non-ASCII byte in a file could load differently depending on the version.
for _, path in ipairs(IN_GAME_FILES) do
    test(path .. " is pure ASCII", function()
        local src, line = read(path), 1
        for i = 1, #src do
            local b = src:byte(i)
            if b == 10 then line = line + 1 end
            if b > 127 then error("non-ASCII byte " .. b .. " on line " .. line, 0) end
        end
    end)
end

-- Replaces comments and string literals by spaces (keeping newlines), so only
-- code is left to check.
local function codeOnly(src)
    local out, i, n = {}, 1, #src
    local function blank(s) return (s:gsub("[^\n]", " ")) end
    while i <= n do
        local c = src:sub(i, i)
        local long = src:match("^%-%-%[(=*)%[", i) or src:match("^%[(=*)%[", i)
        if long then
            local open = src:match("^%-%-", i) and ("--[" .. long .. "[") or ("[" .. long .. "[")
            local _, close = src:find("]" .. long .. "]", i + #open, true)
            close = close or n
            out[#out + 1] = blank(src:sub(i, close))
            i = close + 1
        elseif src:match("^%-%-", i) then
            local e = src:find("\n", i, true) or n + 1
            out[#out + 1] = blank(src:sub(i, e - 1))
            i = e
        elseif c == '"' or c == "'" then
            local j = i + 1
            while j <= n do
                local d = src:sub(j, j)
                if d == "\\" then j = j + 2
                elseif d == c then break
                else j = j + 1 end
            end
            out[#out + 1] = blank(src:sub(i, j))
            i = j + 1
        else
            out[#out + 1] = c
            i = i + 1
        end
    end
    return table.concat(out)
end

-- Lua features that the desktop test runtimes (5.3, 5.4) have but CC:Tweaked's
-- Cobalt does not: https://tweaked.cc/reference/feature_compat.html
local UNSUPPORTED = {
    { "//", "floor division operator" },
    { "&", "bitwise and operator (use bit32.band)" },
    { "|", "bitwise or operator (use bit32.bor)" },
    { "<<", "shift operator (use bit32.lshift)" },
    { ">>", "shift operator (use bit32.rshift)" },
    { "~[^=]", "bitwise xor/not operator (use bit32.bxor/bnot)" },
    { "math%.type", "math.type" },
    { "math%.tointeger", "math.tointeger" },
    { "math%.ult", "math.ult" },
    { "math%.maxinteger", "math.maxinteger" },
    { "math%.mininteger", "math.mininteger" },
    { "collectgarbage", "collectgarbage" },
    { "string%.dump", "string.dump" },
    { "os%.exit", "os.exit" },
    { "os%.execute", "os.execute" },
    { "table%.setn", "table.setn" },
    { "gcinfo", "gcinfo" },
}

for _, path in ipairs(IN_GAME_FILES) do
    test(path .. " only uses Lua features CC:Tweaked supports", function()
        local code = codeOnly(read(path))
        for _, rule in ipairs(UNSUPPORTED) do
            local at = code:find(rule[1])
            if at then
                local _, lines = code:sub(1, at):gsub("\n", "")
                error(rule[2] .. " on line " .. (lines + 1), 0)
            end
        end
    end)
end

test("the source check finds forbidden features and ignores strings and comments", function()
    ok(codeOnly("local a = 1 // 2"):find("//"))
    ok(not codeOnly('local s = "a // b" -- x & y'):find("[/&]"))
    ok(not codeOnly("--[[ a | b ]] local x = [==[ c >> d ]==]"):find("[|>]"))
    ok(codeOnly("x = a ~ b"):find("~[^=]"))
    ok(not codeOnly("if a ~= b then end"):find("~[^=]"))
    ok(codeOnly("local t = math.type(1)"):find("math%.type"))
end)
