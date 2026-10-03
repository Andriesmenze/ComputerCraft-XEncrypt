-- Converts between text and "U+XXXX" code point notation.
--
-- Strings in CC:Tweaked are bytes, and the terminal draws each byte as one
-- character; bytes 0xA0-0xFF look like ISO-8859-1. Input text is read as UTF-8
-- where it is valid UTF-8, and any other byte as the code point with the same
-- value (ISO-8859-1). For 0xA0-0xFF that is the character CC shows; CC's drawing
-- characters 0x80-0x9F become the control code points U+0080-U+009F, not
-- look-alike block characters. A CC string which happens to be valid UTF-8 is
-- read as one UTF-8 character: "\195\169" becomes "U+00E9", and so does
-- natural in-game text such as "\223\171" (sharp s, then a guillemet). For text
-- typed in game or read in text mode, pass fromCC = true to transcodeUTF8String
-- so that every byte is one character.
--
-- To get UTF-8 from outside the game unchanged on every CC:Tweaked version,
-- read it as bytes: fs.open(path, "rb") or http.get(url, headers, true). Before
-- CC:Tweaked 1.109, text-mode reads turn every character above U+00FF into "?".
--
-- Output text uses the CC charset by default (one byte per character, "?" for
-- code points above U+00FF); pass asUTF8 = true to get UTF-8 instead. Write
-- UTF-8 output with fs.open(path, "wb"): before 1.109, text-mode writes and
-- HTTP request bodies re-encode every byte from 0x80 up.
--
-- Notation: "U+" (any case) and 4 to 6 hex digits; a leading zero only pads to
-- 4 digits, so "U+00E9" is valid and "U+0000E9" is not.

Unicode_VERSION = "0.2"

local byte, char, format = string.byte, string.char, string.format
local concat, floor = table.concat, math.floor

-- Returns the code point at byte position i of s and its length in bytes.
local function decodeAt(s, i)
    local a, b, c, d = byte(s, i, i + 3)
    if a < 0x80 then
        return a, 1
    end
    local b2 = b and b >= 0x80 and b <= 0xBF
    local c3 = b2 and c and c >= 0x80 and c <= 0xBF
    local d4 = c3 and d and d >= 0x80 and d <= 0xBF
    if a >= 0xC2 and a <= 0xDF and b2 then
        return (a - 0xC0) * 64 + (b - 0x80), 2
    elseif a >= 0xE0 and a <= 0xEF and c3 and not (a == 0xE0 and b < 0xA0) and not (a == 0xED and b > 0x9F) then
        return ((a - 0xE0) * 64 + (b - 0x80)) * 64 + (c - 0x80), 3
    elseif a >= 0xF0 and a <= 0xF4 and d4 and not (a == 0xF0 and b < 0x90) and not (a == 0xF4 and b > 0x8F) then
        return (((a - 0xF0) * 64 + (b - 0x80)) * 64 + (c - 0x80)) * 64 + (d - 0x80), 4
    end
    -- Not UTF-8: the byte itself, as CC shows it.
    return a, 1
end

local function encodeUTF8(cp)
    if cp < 0x80 then
        return char(cp)
    elseif cp < 0x800 then
        return char(0xC0 + floor(cp / 64), 0x80 + cp % 64)
    elseif cp < 0x10000 then
        return char(0xE0 + floor(cp / 4096), 0x80 + floor(cp / 64) % 64, 0x80 + cp % 64)
    end
    return char(0xF0 + floor(cp / 262144), 0x80 + floor(cp / 4096) % 64, 0x80 + floor(cp / 64) % 64, 0x80 + cp % 64)
end

local function codeNotation(cp)
    return format("U+%04X", cp)
end

-- Parses the hex digits of a code point; nil if it is not a Unicode scalar value.
local function parseCode(hex)
    local cp = tonumber(hex, 16)
    if not cp or cp > 0x10FFFF or (cp >= 0xD800 and cp <= 0xDFFF) then
        return nil
    end
    return cp
end

local function toCharacter(cp, asUTF8)
    if asUTF8 then
        return encodeUTF8(cp)
    end
    return cp <= 0xFF and char(cp) or "?"
end

local function expectString(value, name)
    if type(value) ~= "string" then
        error(format("bad argument #1 to '%s' (string expected, got %s)", name, type(value)), 3)
    end
end

-- "\195\169" (e acute in UTF-8) -> "U+00E9". Returns nil unless the input is
-- exactly one character.
function transcodeUTF8Character(utf8_Character)
    expectString(utf8_Character, "transcodeUTF8Character")
    if utf8_Character == "" then
        return nil
    end
    local cp, length = decodeAt(utf8_Character, 1)
    if length ~= #utf8_Character then
        return nil
    end
    return codeNotation(cp)
end

-- "U+00E9" (or "u+00e9") -> "\233" (e acute). Returns nil if the input is not exactly one
-- code point in "U+" notation with 4 to 6 hex digits.
function transcodeUnicodeCharacter(unicode_Character, asUTF8)
    expectString(unicode_Character, "transcodeUnicodeCharacter")
    local hex = unicode_Character:match("^[Uu]%+(%x%x%x%x%x?%x?)$")
    if hex and #hex > 4 and hex:sub(1, 1) == "0" then
        return nil -- leading zeros only pad to 4 digits, as in transcodeUnicodeString
    end
    local cp = hex and parseCode(hex)
    if not cp then
        return nil
    end
    return toCharacter(cp, asUTF8)
end

-- "H\233" -> "U+0048U+00E9". With fromCC = true every byte is one character
-- (the CC charset), which is what text typed in game is.
function transcodeUTF8String(utf8_String, fromCC)
    expectString(utf8_String, "transcodeUTF8String")
    local out, i, n = {}, 1, #utf8_String
    while i <= n do
        local cp, length
        if fromCC then
            cp, length = byte(utf8_String, i), 1
        else
            cp, length = decodeAt(utf8_String, i)
        end
        out[#out + 1] = codeNotation(cp)
        i = i + length
    end
    return concat(out)
end

-- "U+0048U+00E9" -> "H\233". Text that is not in "U+" notation is skipped and
-- invalid code points become "?". A code takes up to 6 hex digits, so separate
-- one that does not start with 0 from following hex text ("U+20AC 1", not
-- "U+20AC1").
function transcodeUnicodeString(unicode_String, asUTF8)
    expectString(unicode_String, "transcodeUnicodeString")
    local out, pos = {}, 1
    while true do
        local _, last, hex = unicode_String:find("[Uu]%+(%x%x%x%x%x?%x?)", pos)
        if not last then break end
        -- Leading zeros only pad to 4 digits, so in "U+00C9cole" the code is
        -- U+00C9 and "c" is following text, not a fifth digit.
        while #hex > 4 and hex:sub(1, 1) == "0" do
            hex, last = hex:sub(1, -2), last - 1
        end
        local cp = parseCode(hex)
        out[#out + 1] = cp and toCharacter(cp, asUTF8) or "?"
        pos = last + 1
    end
    return concat(out)
end
