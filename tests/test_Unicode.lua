-- Tests for apis/Unicode.lua.

local A = cc.newComputer(1)
local U = A:loadAPI("apis/Unicode.lua")

test("public API", function()
    local names = {}
    for k in pairs(U) do names[#names + 1] = k end
    table.sort(names)
    eq(names, { "Unicode_VERSION", "transcodeUTF8Character", "transcodeUTF8String",
        "transcodeUnicodeCharacter", "transcodeUnicodeString" })
end)

test("ASCII round trip, including characters the old table missed", function()
    eq(U.transcodeUTF8String("A b\\~"), "U+0041U+0020U+0062U+005CU+007E")
    eq(U.transcodeUnicodeString("U+0041U+0020U+0062U+005CU+007E"), "A b\\~")
    eq(U.transcodeUTF8String("\n\t"), "U+000AU+0009")
    eq(U.transcodeUnicodeString("U+000AU+0009"), "\n\t")
end)

test("every CC character (single byte) round trips", function()
    for b = 0, 255 do
        local c = string.char(b)
        local code = string.format("U+%04X", b)
        eq(U.transcodeUTF8Character(c), code, "byte " .. b)
        eq(U.transcodeUTF8String(c), code, "byte " .. b)
        eq(U.transcodeUnicodeCharacter(code), c, "code " .. code)
        eq(U.transcodeUnicodeString(code), c, "code " .. code)
    end
end)

test("a string of all bytes in order round trips", function()
    local t = {}
    for b = 0, 255 do t[#t + 1] = string.char(b) end
    local all = table.concat(t)
    eq(U.transcodeUnicodeString(U.transcodeUTF8String(all)), all)
end)

test("UTF-8 input is decoded", function()
    eq(U.transcodeUTF8Character("\195\169"), "U+00E9") -- e acute
    eq(U.transcodeUTF8String("caf\195\169"), "U+0063U+0061U+0066U+00E9")
    eq(U.transcodeUTF8String("\226\130\172"), "U+20AC") -- euro sign
    eq(U.transcodeUTF8String("\240\159\152\128"), "U+1F600") -- emoji
end)

test("output in the CC charset by default, UTF-8 on request", function()
    eq(U.transcodeUnicodeCharacter("U+00E9"), "\233")
    eq(U.transcodeUnicodeCharacter("U+00E9", true), "\195\169")
    eq(U.transcodeUnicodeCharacter("U+20AC"), "?")
    eq(U.transcodeUnicodeCharacter("U+20AC", true), "\226\130\172")
    eq(U.transcodeUnicodeCharacter("U+1F600", true), "\240\159\152\128")
    local text = "x\195\169\226\130\172\240\159\152\128"
    eq(U.transcodeUnicodeString(U.transcodeUTF8String(text), true), text)
    eq(U.transcodeUnicodeString(U.transcodeUTF8String(text)), "x\233??")
end)

test("lowercase notation is accepted", function()
    eq(U.transcodeUnicodeCharacter("u+00e9"), "\233")
    eq(U.transcodeUnicodeString("u+0041U+00e9"), "A\233")
end)

test("invalid UTF-8 falls back to single bytes", function()
    eq(U.transcodeUTF8String("\192\128"), "U+00C0U+0080") -- overlong NUL
    eq(U.transcodeUTF8String("\237\160\128"), "U+00EDU+00A0U+0080") -- surrogate
    eq(U.transcodeUTF8String("\195"), "U+00C3") -- truncated
    eq(U.transcodeUTF8String("\244\144\128\128"), "U+00F4U+0090U+0080U+0080") -- above U+10FFFF
end)

test("transcodeUTF8Character needs exactly one character", function()
    eq(U.transcodeUTF8Character(""), nil)
    eq(U.transcodeUTF8Character("ab"), nil)
    eq(U.transcodeUTF8Character("\195\169x"), nil)
end)

test("leading zeros only pad to 4 digits, so following hex text is not swallowed", function()
    eq(U.transcodeUnicodeString("U+00C9cole", true), "\195\137")
    eq(U.transcodeUnicodeString("U+0041BC"), "A")
    eq(U.transcodeUnicodeString("Price: U+00A3100"), "\163")
    eq(U.transcodeUnicodeString("u+00e9e"), "\233")
    eq(U.transcodeUnicodeString("U+01F600", true), "\199\182", "a leading zero means exactly 4 digits: U+01F6, then '00'")
    eq(U.transcodeUnicodeString("U+1F600", true), "\240\159\152\128")
    for cp = 0, 0xFFF, 17 do
        eq(U.transcodeUnicodeString(string.format("U+%04Xabc", cp), true),
            U.transcodeUnicodeCharacter(string.format("U+%04X", cp), true), "cp " .. cp)
    end
    -- Codes without a leading zero take up to 6 digits, as documented.
    eq(U.transcodeUnicodeString("U+20AC 1", true), "\226\130\172")
    eq(U.transcodeUnicodeString("U+110000"), "?")
end)

test("UTF-8 boundaries", function()
    -- Edges of each encoded length and of the valid code point range.
    local cases = {
        { "U+007F", "\127" }, { "U+0080", "\194\128" }, { "U+07FF", "\223\191" },
        { "U+0800", "\224\160\128" }, { "U+D7FF", "\237\159\191" }, { "U+E000", "\238\128\128" },
        { "U+FFFF", "\239\191\191" }, { "U+10000", "\240\144\128\128" }, { "U+10FFFF", "\244\143\191\191" },
    }
    for _, c in ipairs(cases) do
        eq(U.transcodeUnicodeCharacter(c[1], true), c[2], c[1] .. " encodes")
        eq(U.transcodeUTF8String(c[2]), c[1], c[1] .. " decodes")
    end
    eq(U.transcodeUnicodeCharacter("U+D800", true), nil)
    eq(U.transcodeUnicodeCharacter("U+DFFF", true), nil)
    eq(U.transcodeUnicodeCharacter("U+110000", true), nil)
    eq(U.transcodeUnicodeCharacter("U+00FF"), "\255")
    eq(U.transcodeUnicodeCharacter("U+0100"), "?")
    -- Sequences just outside the valid forms fall back to single bytes.
    eq(U.transcodeUTF8String("\193\191"), "U+00C1U+00BF") -- overlong 2-byte lead
    eq(U.transcodeUTF8String("\194\127"), "U+00C2U+007F") -- continuation too low
    eq(U.transcodeUTF8String("\224\159\191"), "U+00E0U+009FU+00BF") -- overlong 3-byte
    eq(U.transcodeUTF8String("\240\143\191\191"), "U+00F0U+008FU+00BFU+00BF") -- overlong 4-byte
    eq(U.transcodeUTF8String("\245\128\128\128"), "U+00F5U+0080U+0080U+0080") -- lead above F4
    eq(U.transcodeUTF8String("\226\130\192"), "U+00E2U+0082U+00C0") -- bad last continuation
end)

test("both parsers follow the same notation rule", function()
    for _, code in ipairs({ "U+0000E9", "U+01F600", "U+010000", "U+00041", "U+0D800" }) do
        eq(U.transcodeUnicodeCharacter(code), nil, code .. " is not canonical")
    end
    for _, code in ipairs({ "U+00E9", "U+1F600", "U+10000", "U+10FFFF", "u+00e9" }) do
        eq(U.transcodeUnicodeString(code, true), U.transcodeUnicodeCharacter(code, true), code)
    end
end)

test("fromCC reads every byte as one character", function()
    local samples = {
        "\187Spa\223\171",          -- German quotes: sharp s + guillemet is also valid UTF-8
        "\171\160caf\233\160\187",  -- French quotes with no-break spaces
        "\195\169",                 -- would be one UTF-8 character
    }
    for _, s in ipairs(samples) do
        local codes = U.transcodeUTF8String(s, true)
        eq(#codes, 6 * #s, "one code per byte")
        eq(U.transcodeUnicodeString(codes), s)
    end
    neq(U.transcodeUTF8String("\223\171"), U.transcodeUTF8String("\223\171", true))
    eq(U.transcodeUTF8String("\223\171", true), "U+00DFU+00AB")
end)

test("invalid notation", function()
    eq(U.transcodeUnicodeCharacter("U+12"), nil)
    eq(U.transcodeUnicodeCharacter("U+0041x"), nil)
    eq(U.transcodeUnicodeCharacter("0041"), nil)
    eq(U.transcodeUnicodeCharacter("U+D800"), nil)
    eq(U.transcodeUnicodeCharacter("U+110000"), nil)
    eq(U.transcodeUnicodeString("U+D800U+0041"), "?A")
    eq(U.transcodeUnicodeString("no codes here"), "")
    eq(U.transcodeUnicodeString(""), "")
    eq(U.transcodeUTF8String(""), "")
end)

test("non-string arguments raise a clear error", function()
    raises(function() U.transcodeUTF8String(nil) end, "string expected")
    raises(function() U.transcodeUnicodeString(5) end, "string expected")
    raises(function() U.transcodeUTF8Character({}) end, "string expected")
    raises(function() U.transcodeUnicodeCharacter(nil) end, "string expected")
end)

test("long input is handled quickly", function()
    local s = string.rep("ab\195\169", 5000)
    eq(U.transcodeUnicodeString(U.transcodeUTF8String(s), true), s)
end)
