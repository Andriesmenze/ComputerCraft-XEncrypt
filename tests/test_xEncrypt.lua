-- Tests for apis/xEncrypt.lua: official test vectors and API behaviour.

local A = cc.newComputer(1)
local X = A:loadAPI("apis/xEncrypt.lua")

local function unhex(h)
    return (h:gsub("%s", ""):gsub("%x%x", function(b) return string.char(tonumber(b, 16)) end))
end
local hex = X.toHex
local function bytesFrom(first, last)
    local t = {}
    for i = first, last do t[#t + 1] = string.char(i) end
    return table.concat(t)
end

test("public API is exactly the documented functions", function()
    local names = {}
    for k in pairs(X) do names[#names + 1] = k end
    table.sort(names)
    eq(names, {
        "addEntropy", "chacha20", "constantTimeEquals", "decrypt", "deriveKey", "encrypt", "fromHex",
        "generateKey", "hashPassword", "hkdf", "hmac", "pbkdf2", "randomBytes", "randomInt", "seed", "sha256",
        "toHex", "verifyPassword", "xEncrypt_VERSION",
    })
end)

---------------------------------------------------------------------------
-- Encoding
---------------------------------------------------------------------------

test("toHex/fromHex round trip every byte value", function()
    local all = bytesFrom(0, 255)
    local h = X.toHex(all)
    eq(#h, 512)
    ok(not h:find("[^0-9a-f]"), "lowercase hex only")
    eq(X.fromHex(h), all)
    eq(X.fromHex(h:upper()), all)
    eq(X.toHex(""), "")
    eq(X.fromHex(""), "")
end)

test("fromHex rejects malformed input", function()
    eq(X.fromHex("abc"), nil)
    eq(X.fromHex("zz"), nil)
    eq(X.fromHex("0x"), nil)
    eq(X.fromHex(" 00"), nil)
    eq(X.fromHex(nil), nil)
    eq(X.fromHex(12), nil)
end)

test("constantTimeEquals", function()
    ok(X.constantTimeEquals("abc", "abc"))
    ok(X.constantTimeEquals("", ""))
    ok(not X.constantTimeEquals("abc", "abd"))
    ok(not X.constantTimeEquals("abc", "ab"))
    ok(not X.constantTimeEquals("abc", nil))
    ok(not X.constantTimeEquals(1, 1))
    -- Differences in several bytes must not cancel out.
    ok(not X.constantTimeEquals("ab", "ba"))
    ok(not X.constantTimeEquals("\1\1", "\0\0"))
end)

---------------------------------------------------------------------------
-- SHA-256 (FIPS 180-4 examples)
---------------------------------------------------------------------------

test("sha256 test vectors", function()
    eq(hex(X.sha256("")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    eq(hex(X.sha256("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    eq(hex(X.sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    eq(hex(X.sha256("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
end)

test("sha256 of one million 'a' (heavy)", function()
    if not cc.heavy then skip("heavy") end
    eq(hex(X.sha256(string.rep("a", 1000000))), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
end)

test("sha256 rejects non-strings", function()
    raises(function() X.sha256(nil) end, "string expected")
    raises(function() X.sha256(5) end, "string expected")
end)

---------------------------------------------------------------------------
-- HMAC-SHA256 (RFC 4231)
---------------------------------------------------------------------------

test("hmac RFC 4231 test cases", function()
    eq(hex(X.hmac(string.rep("\11", 20), "Hi There")),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    eq(hex(X.hmac("Jefe", "what do ya want for nothing?")),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    eq(hex(X.hmac(string.rep("\170", 20), string.rep("\221", 50))),
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
    eq(hex(X.hmac(bytesFrom(1, 25), string.rep("\205", 50))),
        "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b")
    eq(hex(X.hmac(string.rep("\170", 131), "Test Using Larger Than Block-Size Key - Hash Key First")),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    eq(hex(X.hmac(string.rep("\170", 131),
        "This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.")),
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2")
end)

---------------------------------------------------------------------------
-- HKDF (RFC 5869)
---------------------------------------------------------------------------

test("hkdf RFC 5869 test cases 1 and 3", function()
    eq(hex(X.hkdf(string.rep("\11", 22), bytesFrom(0, 12), bytesFrom(0xf0, 0xf9), 42)),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    eq(hex(X.hkdf(string.rep("\11", 22), "", "", 42)),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    eq(hex(X.hkdf(string.rep("\11", 22), nil, nil, 42)),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    eq(X.hkdf("x", "", "", 0), "")
    raises(function() X.hkdf("x", "", "", 8161) end, "length")
    raises(function() X.hkdf("x", "", "", 1.5) end, "length")
end)

---------------------------------------------------------------------------
-- PBKDF2-HMAC-SHA256 (RFC 7914 section 11 and common vectors)
---------------------------------------------------------------------------

test("pbkdf2 test vectors", function()
    eq(hex(X.pbkdf2("passwd", "salt", 1, 64)),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
    eq(hex(X.pbkdf2("password", "salt", 1, 32)), "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
    eq(hex(X.pbkdf2("password", "salt", 2, 32)), "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
    eq(hex(X.pbkdf2("password", "salt", 2)), "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
end)

test("pbkdf2 4096 iterations (heavy)", function()
    if not cc.heavy then skip("heavy") end
    eq(hex(X.pbkdf2("password", "salt", 4096, 32)), "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
end)

test("pbkdf2 validates its arguments", function()
    raises(function() X.pbkdf2("p", "s", 0) end, "iterations")
    raises(function() X.pbkdf2("p", "s", 1.5) end, "iterations")
    raises(function() X.pbkdf2("p", "s", 5001) end, "iterations")
    raises(function() X.hashPassword("p", 5001) end, "'hashPassword' %(iterations")
    raises(function() X.deriveKey("p", "s", 0) end, "'deriveKey' %(iterations")
    eq(#X.pbkdf2("p", "s", 5000, 1), 1, "the cap itself is allowed")
    raises(function() X.pbkdf2("p", "s", 1, 0) end, "length")
    -- The cap bounds iterations times 32-byte output blocks, not iterations alone.
    raises(function() X.pbkdf2("p", "s", 5000, 64) end, "ceil%(length / 32%)")
    raises(function() X.pbkdf2("p", "s", 1000, 1024) end, "ceil%(length / 32%)")
    raises(function() X.pbkdf2("p", "s", 2501, 64) end, "ceil%(length / 32%)")
    eq(#X.pbkdf2("p", "s", 1, 1024), 1024)
    raises(function() X.pbkdf2(nil, "s", 1) end, "string expected")
end)

---------------------------------------------------------------------------
-- ChaCha20 (RFC 8439)
---------------------------------------------------------------------------

local KEY = bytesFrom(0, 31)

test("chacha20 block function (RFC 8439 2.3.2)", function()
    local stream = X.chacha20(KEY, unhex("000000090000004a00000000"), 1, string.rep("\0", 64))
    eq(hex(stream), "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        .. "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
end)

test("chacha20 all-zero key stream (RFC 8439 A.1 #1)", function()
    local stream = X.chacha20(string.rep("\0", 32), string.rep("\0", 12), 0, string.rep("\0", 64))
    eq(hex(stream), "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
        .. "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")
end)

test("chacha20 encryption (RFC 8439 2.4.2)", function()
    local plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    local nonce = unhex("000000000000004a00000000")
    local ciphertext = X.chacha20(KEY, nonce, 1, plaintext)
    eq(hex(ciphertext), "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
        .. "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
        .. "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
        .. "5af90bbf74a35be6b40b8eedf2785e42874d")
    eq(X.chacha20(KEY, nonce, 1, ciphertext), plaintext)
    eq(X.chacha20(KEY, nonce, 1, ""), "")
end)

test("chacha20 validates its arguments", function()
    local nonce = string.rep("\0", 12)
    raises(function() X.chacha20(KEY:sub(2), nonce, 0, "x") end, "32 bytes")
    raises(function() X.chacha20(KEY, nonce:sub(2), 0, "x") end, "12 bytes")
    raises(function() X.chacha20(KEY, nonce, -1, "x") end, "counter")
    raises(function() X.chacha20(KEY, nonce, 0.5, "x") end, "counter")
    raises(function() X.chacha20(KEY, nonce, 4294967295, string.rep("x", 65)) end, "counter")
    eq(#X.chacha20(KEY, nonce, 4294967295, string.rep("x", 64)), 64)
    raises(function() X.chacha20(KEY, nonce, 4294967296, "x") end, "counter")
    if math.maxinteger then -- integer Lua: counter + blocks must not overflow past the check
        raises(function() X.chacha20(KEY, nonce, math.maxinteger, string.rep("x", 128)) end, "counter")
    end
end)

---------------------------------------------------------------------------
-- Random bytes and keys
---------------------------------------------------------------------------

test("randomBytes returns the requested length and differs per call", function()
    eq(X.randomBytes(0), "")
    eq(#X.randomBytes(1), 1)
    eq(#X.randomBytes(100), 100)
    local a, b = X.randomBytes(32), X.randomBytes(32)
    neq(a, b)
    raises(function() X.randomBytes(-1) end, "randomBytes")
    raises(function() X.randomBytes(1.5) end, "randomBytes")
    raises(function() X.randomBytes(0 / 0) end, "randomBytes")
    -- 32 + n must not wrap in Cobalt's 32-bit string.rep count (or overflow on
    -- integer Lua), which would leave the generator with an empty key.
    raises(function() X.randomBytes(16777217) end, "randomBytes")
    raises(function() X.randomBytes(2 ^ 32) end, "randomBytes")
    raises(function() X.randomBytes(math.huge) end, "randomBytes")
    if math.maxinteger then raises(function() X.randomBytes(math.maxinteger) end, "randomBytes") end
    eq(#X.randomBytes(16), 16, "generator still works after rejected calls")
end)

test("generateKey returns 64 lowercase hex characters", function()
    local k1, k2 = X.generateKey(), X.generateKey()
    ok(k1:match("^[0-9a-f]+$") and #k1 == 64, k1)
    neq(k1, k2)
end)

test("seeding writes a seed file and reads it back on the next load", function()
    local B = cc.newComputer(2)
    local XB = B:loadAPI("apis/xEncrypt.lua")
    eq(B.files[".xEncrypt.seed"], nil, "nothing written before first use")
    XB.randomBytes(1)
    local seed1 = B.files[".xEncrypt.seed"]
    ok(seed1 and seed1:match("^[0-9a-f]+$") and #seed1 == 64, "seed file holds 64 hex characters")
    local XB2 = B:loadAPI("apis/xEncrypt.lua")
    XB2.randomBytes(1)
    neq(B.files[".xEncrypt.seed"], seed1, "seed file is replaced on every seeding")
end)

-- A computer whose entropy sources are all fixed, so a test can vary one input
-- at a time. opts.seed is the seed file content; opts.epochEvery = k makes
-- os.epoch("utc") advance 1 ms every k calls (timing jitter); opts.realTostring
-- keeps table addresses; opts.random is what math.random returns; opts.epoch
-- is the real-world time os.epoch("utc") starts at.
local function deterministicComputer(opts)
    opts = opts or {}
    local C = cc.newComputer(opts.id or 42, { clock = 1, epoch = opts.epoch or 7 })
    if not opts.realTostring then
        C.env.tostring = function(v)
            local t = type(v)
            if t == "table" or t == "function" then return t end
            return tostring(v)
        end
    end
    C.env.math = setmetatable({ random = function() return opts.random or 4 end }, { __index = math })
    C.files[".xEncrypt.seed"] = opts.seed
    if opts.epochEvery then
        local calls, now, epoch = 0, 1000, C.env.os.epoch
        C.env.os.epoch = function(kind)
            if kind ~= "utc" then return epoch(kind) end
            calls = calls + 1
            if calls % opts.epochEvery == 0 then now = now + 1 end
            return now
        end
    end
    return C
end

local function firstOutput(opts)
    return deterministicComputer(opts):loadAPI("apis/xEncrypt.lua").randomBytes(32)
end

test("the seed file feeds the generator", function()
    eq(firstOutput(), firstOutput(), "sources are deterministic")
    local a, b = string.rep("a", 64), string.rep("b", 64)
    eq(firstOutput({ seed = a }), firstOutput({ seed = a }))
    neq(firstOutput({ seed = a }), firstOutput({ seed = b }))
    neq(firstOutput({ seed = a }), firstOutput())
    -- A damaged seed file is ignored rather than trusted.
    eq(firstOutput({ seed = "garbage" }), firstOutput())
    eq(firstOutput({ seed = string.rep("A", 64) }), firstOutput())
    eq(firstOutput({ seed = string.rep("a", 65) }), firstOutput())
end)

test("restoring an old seed file (world rollback) does not repeat the random stream", function()
    -- Same computer and the same restored seed file; only the real-world time
    -- differs, as when a world backup is loaded later. Computers reboot on load
    -- and reseed, and the pool includes os.epoch("utc"), so nonces differ.
    local seed = string.rep("c", 64)
    eq(firstOutput({ seed = seed, epoch = 1000 }), firstOutput({ seed = seed, epoch = 1000 }), "only the time differs")
    neq(firstOutput({ seed = seed, epoch = 1000 }), firstOutput({ seed = seed, epoch = 1001 }))
end)

test("each source another player cannot know changes the key", function()
    -- Timing jitter: the loop counts how many calls fit in one clock tick.
    eq(firstOutput({ epochEvery = 3 }), firstOutput({ epochEvery = 3 }))
    neq(firstOutput({ epochEvery = 3 }), firstOutput({ epochEvery = 7 }), "jitter counts are used")
    -- Table and function addresses.
    neq(firstOutput({ realTostring = true }), firstOutput({ realTostring = true }), "addresses are used")
    -- math.random's startup state.
    neq(firstOutput({ random = 0.25 }), firstOutput({ random = 0.5 }), "math.random is used")
end)

test("one random output does not reveal the next, and the seed file reveals no output", function()
    local C = cc.newComputer(46)
    local XC = C:loadAPI("apis/xEncrypt.lua")
    XC.seed()
    local seedKey = XC.fromHex(C.files[".xEncrypt.seed"])
    local a, b = XC.randomBytes(32), XC.randomBytes(32)
    local zero12 = string.rep("\0", 12)
    ok(not XC.chacha20(a, zero12, 0, string.rep("\0", 64)):find(b, 1, true), "an output is the next generator key")
    local fromSeed = XC.chacha20(seedKey, zero12, 0, string.rep("\0", 128))
    ok(not fromSeed:find(a, 1, true) and not fromSeed:find(b, 1, true), "the seed file holds the live generator key")
end)

test("seeding finishes when the clock never moves", function()
    local C = cc.newComputer(43)
    C.env.os.epoch = function() return 1000 end
    eq(#C:loadAPI("apis/xEncrypt.lua").randomBytes(8), 8)
end)

test("seed() seeds once", function()
    local C = cc.newComputer(44)
    local XC = C:loadAPI("apis/xEncrypt.lua")
    XC.seed()
    local seedFile = C.files[".xEncrypt.seed"]
    ok(seedFile, "seed file written")
    XC.seed()
    eq(C.files[".xEncrypt.seed"], seedFile, "second call does nothing")
end)

test("randomInt stays in range and covers it", function()
    local seen = {}
    for _ = 1, 400 do
        local v = X.randomInt(3, 8)
        ok(v >= 3 and v <= 8 and v % 1 == 0, tostring(v))
        seen[v] = true
    end
    for v = 3, 8 do ok(seen[v], "value " .. v .. " appears") end
    eq(X.randomInt(5, 5), 5)
    local big = X.randomInt(0, 4294967295)
    ok(big >= 0 and big <= 4294967295)
    raises(function() X.randomInt(2, 1) end, "randomInt")
    raises(function() X.randomInt(1.5, 3) end, "randomInt")
    raises(function() X.randomInt(0, 4294967296) end, "randomInt")
    raises(function() X.randomInt(nil, 3) end, "randomInt")
    -- Beyond 2^53 doubles cannot represent every integer.
    eq(X.randomInt(2 ^ 53, 2 ^ 53), 2 ^ 53)
    raises(function() X.randomInt(2 ^ 53, 2 ^ 53 + 2) end, "randomInt")
    raises(function() X.randomInt(-2 ^ 53 - 2, -2 ^ 53) end, "randomInt")
    for _ = 1, 50 do
        local v = X.randomInt(2 ^ 53 - 2, 2 ^ 53)
        ok(v >= 2 ^ 53 - 2 and v <= 2 ^ 53, tostring(v))
    end
    if math.maxinteger then
        raises(function() X.randomInt(math.mininteger, math.maxinteger) end, "randomInt")
        raises(function() X.randomInt(-2 ^ 62, 2 ^ 62) end, "randomInt")
    end
end)

test("randomInt is not biased towards low values", function()
    -- With plain modulo instead of rejection sampling, values below 2^30 would
    -- come up half of the time for this range instead of a third.
    local low, n = 0, 3000
    for _ = 1, n do
        if X.randomInt(0, 3 * 2 ^ 30 - 1) < 2 ^ 30 then low = low + 1 end
    end
    ok(low / n > 0.28 and low / n < 0.39, "fraction below 2^30: " .. low / n)
end)

test("addEntropy data reaches the seed file at the next random draw", function()
    local function nextBoot(secret)
        local C = deterministicComputer({ id = 45 })
        local XC = C:loadAPI("apis/xEncrypt.lua")
        XC.seed()
        local before = C.files[".xEncrypt.seed"]
        if secret then XC.addEntropy(secret) end
        eq(C.files[".xEncrypt.seed"], before, "addEntropy itself does not write the disk")
        XC.randomBytes(1)
        if secret then neq(C.files[".xEncrypt.seed"], before, "the next draw saves it") end
        XC.randomBytes(1)
        local saved = C.files[".xEncrypt.seed"]
        -- "Reboot" the same computer and look at its first output.
        return C:loadAPI("apis/xEncrypt.lua").randomBytes(16), saved
    end
    local a = nextBoot("key presses A")
    local b = nextBoot("key presses B")
    neq(a, b, "the next boot depends on the entropy added in this one")
    eq(nextBoot("key presses A"), a)
end)

test("a read-only disk does not break random generation", function()
    local C = cc.newComputer(3)
    C.readOnly = true
    local XC = C:loadAPI("apis/xEncrypt.lua")
    eq(#XC.randomBytes(16), 16)
end)

test("two computers with the same ID and clocks get different streams", function()
    -- Everything public is equal, so only the secret sources can tell them apart.
    local P = cc.newComputer(10, { clock = 1, epoch = 5 })
    local Q = cc.newComputer(10, { clock = 1, epoch = 5 })
    neq(P:loadAPI("apis/xEncrypt.lua").randomBytes(32), Q:loadAPI("apis/xEncrypt.lua").randomBytes(32))
end)

test("addEntropy works before the first random draw and accepts strings only", function()
    local C = cc.newComputer(47)
    local XC = C:loadAPI("apis/xEncrypt.lua")
    XC.addEntropy("key press at 12345")
    ok(C.files[".xEncrypt.seed"], "seeded by addEntropy")
    eq(#XC.randomBytes(8), 8)
    raises(function() XC.addEntropy(5) end, "string expected")
end)

---------------------------------------------------------------------------
-- encrypt / decrypt
---------------------------------------------------------------------------

local key = X.generateKey()

test("known-answer token (the wire format)", function()
    -- Built independently with tests/reference.py (key 00..1f, nonce 40..4b),
    -- so subkey labels, counter and aad framing cannot change unnoticed even
    -- where the cryptography package is missing.
    local kat = "01404142434445464748494a4ba370fef451c76352cdb4e4c0f4064730f45095"
        .. "9881e151faf72f4fb6741f812b9c3517816bd9c8c6c92e3da50e20"
    eq(X.decrypt(hex(KEY), kat, "from 7"), "attack at dawn")
    eq({ X.decrypt(hex(KEY), kat, "from 8") }, { nil, "authentication failed" })
end)

test("encrypt/decrypt round trip", function()
    for _, plaintext in ipairs({ "", "hello", bytesFrom(0, 255), string.rep("long message ", 100) }) do
        local token = X.encrypt(key, plaintext)
        ok(token:match("^[0-9a-f]+$"), "token is lowercase hex")
        eq(#token, 2 * (1 + 12 + #plaintext + 32), "token length")
        eq(X.decrypt(key, token), plaintext)
        eq(X.decrypt(key:upper(), token), plaintext, "upper case keys work")
    end
end)

test("encrypting the same plaintext twice gives different tokens", function()
    neq(X.encrypt(key, "same"), X.encrypt(key, "same"))
end)

test("additional authenticated data must match", function()
    local token = X.encrypt(key, "secret", "sender 7")
    eq(X.decrypt(key, token, "sender 7"), "secret")
    eq({ X.decrypt(key, token, "sender 8") }, { nil, "authentication failed" })
    eq({ X.decrypt(key, token) }, { nil, "authentication failed" })
    eq({ X.decrypt(key, X.encrypt(key, "secret"), "sender 7") }, { nil, "authentication failed" })
end)

test("aad framing: moving a ciphertext byte into the aad is detected", function()
    -- Without the aad length in the tag, header..aad..ciphertext would be
    -- identical for (aad "a", ciphertext c) and (aad "a"..c, empty ciphertext).
    local raw = X.fromHex(X.encrypt(key, "X", "a"))
    local header, c, tag = raw:sub(1, 13), raw:sub(14, 14), raw:sub(15)
    eq({ X.decrypt(key, X.toHex(header .. tag), "a" .. c) }, { nil, "authentication failed" })
end)

test("wrong key fails authentication", function()
    eq({ X.decrypt(X.generateKey(), X.encrypt(key, "secret")) }, { nil, "authentication failed" })
end)

test("every modified byte is detected", function()
    local token = X.encrypt(key, "attack at dawn")
    local raw = X.fromHex(token)
    for i = 2, #raw do
        local flipped = raw:sub(1, i - 1) .. string.char((raw:byte(i) + 1) % 256) .. raw:sub(i + 1)
        eq({ X.decrypt(key, X.toHex(flipped)) }, { nil, "authentication failed" }, "byte " .. i)
    end
    local badVersion = "\2" .. raw:sub(2)
    eq({ X.decrypt(key, X.toHex(badVersion)) }, { nil, "unsupported token version" })
    -- The same bit flipped in two tag bytes: differences must not cancel out.
    for bit = 0, 7 do
        local m = 2 ^ bit
        local function flip(b) return string.char((b % (2 * m) >= m) and b - m or b + m) end
        local n = #raw
        local forged = raw:sub(1, n - 2) .. flip(raw:byte(n - 1)) .. flip(raw:byte(n))
        eq({ X.decrypt(key, X.toHex(forged)) }, { nil, "authentication failed" }, "bit " .. bit)
    end
end)

test("malformed tokens are rejected without raising", function()
    eq({ X.decrypt(key, nil) }, { nil, "invalid token" })
    eq({ X.decrypt(key, 42) }, { nil, "invalid token" })
    eq({ X.decrypt(key, "") }, { nil, "invalid token" })
    eq({ X.decrypt(key, "zz") }, { nil, "invalid token" })
    eq({ X.decrypt(key, string.rep("0", 89)) }, { nil, "invalid token" })
    eq({ X.decrypt(key, string.rep("0", 88)) }, { nil, "invalid token" })
    local token = X.encrypt(key, "x")
    eq({ X.decrypt(key, token:sub(1, -3)) }, { nil, "authentication failed" })
    eq({ X.decrypt(key, token:upper()) }, { nil, "invalid token" }, "tokens are canonical lowercase hex")
    eq({ X.decrypt(key, " " .. token:sub(2)) }, { nil, "invalid token" })
    -- Odd lengths long enough to pass the other checks.
    eq({ X.decrypt(key, token .. "0") }, { nil, "invalid token" })
    eq({ X.decrypt(key, token:sub(1, -2)) }, { nil, "invalid token" })
end)

test("decrypt rejects tokens longer than maxLength before doing any work", function()
    local token = X.encrypt(key, string.rep("m", 100))
    eq(X.decrypt(key, token, nil, 100), string.rep("m", 100))
    eq({ X.decrypt(key, token, nil, 99) }, { nil, "token too long" })
    -- Default cap is 65536 bytes of plaintext; a forged oversized token is
    -- rejected by length alone.
    eq({ X.decrypt(key, string.rep("0", 2 * (45 + 65537))) }, { nil, "token too long" })
    eq({ X.decrypt(key, string.rep("z", 2 * (45 + 65537))) }, { nil, "token too long" }, "size is checked before content")
    -- Exactly 65536 bytes passes the default size check (and then fails the tag).
    eq({ X.decrypt(key, "01" .. string.rep("0", 2 * (44 + 65536))) }, { nil, "authentication failed" })
    raises(function() X.decrypt(key, token, nil, "big") end, "non%-negative")
    raises(function() X.decrypt(key, token, nil, 0 / 0) end, "non%-negative")
    raises(function() X.decrypt(key, token, nil, -1) end, "non%-negative")
    eq(X.decrypt(key, token, nil, math.huge), string.rep("m", 100), "math.huge means no limit")
end)

test("decrypt accepts exactly 65536 bytes by default (heavy)", function()
    if not cc.heavy then skip("heavy") end
    local big = string.rep("z", 65536)
    eq(X.decrypt(key, X.encrypt(key, big)), big)
    eq({ X.decrypt(key, X.encrypt(key, big .. "z")) }, { nil, "token too long" })
    eq(X.decrypt(key, X.encrypt(key, big .. "z"), nil, 65537), big .. "z")
end)

test("bad keys and arguments raise", function()
    raises(function() X.encrypt("short", "x") end, "64 hexadecimal")
    raises(function() X.encrypt(string.rep("g", 64), "x") end, "64 hexadecimal")
    raises(function() X.encrypt(nil, "x") end, "64 hexadecimal")
    raises(function() X.decrypt(12, "00") end, "64 hexadecimal")
    raises(function() X.encrypt(key, nil) end, "string expected")
    raises(function() X.encrypt(key, "x", 5) end, "string expected")
end)

test("tokens can be decrypted on another computer with the same key", function()
    local B = cc.newComputer(20)
    local XB = B:loadAPI("apis/xEncrypt.lua")
    eq(XB.decrypt(key, X.encrypt(key, "over rednet", "from 1"), "from 1"), "over rednet")
end)

test("tokens survive textutils.serialize and settings", function()
    local token = X.encrypt(key, bytesFrom(0, 255))
    A.env.settings.set("token", token)
    A.env.settings.save(".settings")
    A.env.settings.clear()
    A.env.settings.load(".settings")
    eq(X.decrypt(key, A.env.settings.get("token")), bytesFrom(0, 255))
end)

---------------------------------------------------------------------------
-- Keys from passwords, password hashing
---------------------------------------------------------------------------

test("deriveKey is deterministic and depends on salt and password", function()
    local k = X.deriveKey("correct horse", "salt", 10)
    eq(#k, 64)
    eq(X.deriveKey("correct horse", "salt", 10), k)
    neq(X.deriveKey("correct horse", "pepper", 10), k)
    neq(X.deriveKey("correct horsf", "salt", 10), k)
    eq(X.decrypt(k, X.encrypt(k, "ok")), "ok")
end)

test("deriveKey default matches the README example (1000 iterations)", function()
    -- Value from Python's hashlib.pbkdf2_hmac("sha256", ..., 1000, 32).
    eq(X.deriveKey("correct horse battery staple", "my-app"),
        "eaf65d5d722a96ee0d110dd741e3ad951fbbd8a5bae7663f08e49e82dccf1781")
end)

test("hashPassword and verifyPassword", function()
    local stored = X.hashPassword("hunter2", 10)
    ok(stored:match("^pbkdf2%-sha256%$10%$%x+%$%x+$"), stored)
    ok(X.verifyPassword("hunter2", stored))
    ok(not X.verifyPassword("hunter3", stored))
    ok(not X.verifyPassword("", stored))
    neq(X.hashPassword("hunter2", 10), stored, "random salt")
    local blank = X.hashPassword("", 10)
    ok(X.verifyPassword("", blank))
    ok(not X.verifyPassword(" ", blank))
end)

test("hashPassword default iteration count", function()
    local stored = X.hashPassword("pw")
    ok(stored:match("^pbkdf2%-sha256%$1000%$"), stored)
    ok(X.verifyPassword("pw", stored))
end)

test("verifyPassword rejects malformed stored values", function()
    local stored = X.hashPassword("pw", 5)
    ok(not X.verifyPassword("pw", nil))
    ok(not X.verifyPassword(nil, stored))
    ok(not X.verifyPassword("pw", ""))
    ok(not X.verifyPassword("pw", "pw"))
    ok(not X.verifyPassword("pw", stored:gsub("^pbkdf2", "md5")))
    ok(not X.verifyPassword("pw", stored:gsub("%$5%$", "$0$")))
    ok(not X.verifyPassword("pw", stored:gsub("%$5%$", "$99999999$")))
    ok(not X.verifyPassword("pw", stored .. "0"), "odd length hash")
    ok(not X.verifyPassword("pw", stored:sub(1, -40)), "truncated hash")
    raises(function() X.hashPassword(nil) end, "string expected")
end)
