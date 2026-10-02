-- xEncrypt: authenticated encryption, hashing and password storage for
-- ComputerCraft / CC:Tweaked, in pure Lua.
--
--   os.loadAPI("apis/xEncrypt.lua")
--   local key = xEncrypt.generateKey()               -- 64 hex characters, share it with the peer
--   local token = xEncrypt.encrypt(key, "hello")     -- hex string, safe for rednet, files and settings
--   local text, err = xEncrypt.decrypt(key, token)   -- "hello", or nil and a reason
--   local stored = xEncrypt.hashPassword("secret")   -- store this, not the password
--   xEncrypt.verifyPassword("secret", stored)        -- true
--
-- Primitives: SHA-256, HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA256 and ChaCha20
-- (RFC 8439), checked against the official test vectors in tests/.
-- encrypt() is ChaCha20 + HMAC-SHA256 (encrypt-then-MAC) with a random 96 bit nonce.
--
-- Errors: wrong argument types or malformed keys raise an error (programming
-- mistakes); a token that is malformed, tampered with or encrypted with another
-- key makes decrypt() return nil and a message.
--
-- Randomness: CC has no secure random source. On first use (or seed()) the
-- generator is seeded from clocks, IDs, math.random, table addresses and timing
-- jitter, plus the seed file "/.xEncrypt.seed", which is rewritten so entropy
-- accumulates over reboots. Call addEntropy() with anything unpredictable you
-- have (key press timings, received messages) to strengthen it.
--
-- The library never yields; keep single calls well below CC's 7 second limit.

xEncrypt_VERSION = "1.0"

local bit32 = bit32
if not bit32 then
    error("xEncrypt needs the bit32 library", 0)
end
local band, bor, bxor, bnot = bit32.band, bit32.bor, bit32.bxor, bit32.bnot
local rshift, lrotate, rrotate = bit32.rshift, bit32.lrotate, bit32.rrotate
local byte, char, rep, format = string.byte, string.char, string.rep, string.format
local concat = table.concat
local floor, ceil = math.floor, math.ceil
local unpack = table.unpack or unpack

local MOD32 = 4294967296
local SEED_FILE = "/.xEncrypt.seed"
local DEFAULT_ITERATIONS = 1000
local MAX_ITERATIONS = 10000 -- more would not finish within CC's 7 s limit on a busy server
local DEFAULT_MAX_LENGTH = 65536

local function expectString(value, index, name)
    if type(value) ~= "string" then
        error(format("bad argument #%d to '%s' (string expected, got %s)", index, name, type(value)), 3)
    end
end

local function be32(x)
    return char(floor(x / 16777216) % 256, floor(x / 65536) % 256, floor(x / 256) % 256, x % 256)
end

local function be64(x)
    local t = {}
    for i = 8, 1, -1 do
        t[i] = char(x % 256)
        x = floor(x / 256)
    end
    return concat(t)
end

local function le32(s, i)
    local a, b, c, d = byte(s, i, i + 3)
    return ((d * 256 + c) * 256 + b) * 256 + a
end

---------------------------------------------------------------------------
-- Encoding helpers
---------------------------------------------------------------------------

function toHex(data)
    expectString(data, 1, "toHex")
    return (data:gsub(".", function(c) return format("%02x", byte(c)) end))
end

-- Returns nil for anything that is not an even-length hexadecimal string.
function fromHex(hex)
    if type(hex) ~= "string" or #hex % 2 ~= 0 or hex:find("[^%x]") then
        return nil
    end
    return (hex:gsub("%x%x", function(h) return char(tonumber(h, 16)) end))
end

-- Compares two strings in time that depends only on their length.
function constantTimeEquals(a, b)
    if type(a) ~= "string" or type(b) ~= "string" or #a ~= #b then
        return false
    end
    local diff = 0
    for i = 1, #a do
        diff = bor(diff, bxor(byte(a, i), byte(b, i)))
    end
    return diff == 0
end

---------------------------------------------------------------------------
-- SHA-256 (FIPS 180-4)
---------------------------------------------------------------------------

local K256 = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}
local IV256 = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 }

-- Processes the 64 byte block of `data` that starts at `offset` into state H.
local function compress(H, data, offset)
    local w = {}
    for t = 0, 15 do
        local a, b, c, d = byte(data, offset + 4 * t, offset + 4 * t + 3)
        w[t] = ((a * 256 + b) * 256 + c) * 256 + d
    end
    for t = 16, 63 do
        local x, y = w[t - 15], w[t - 2]
        local s0 = bxor(rrotate(x, 7), rrotate(x, 18), rshift(x, 3))
        local s1 = bxor(rrotate(y, 17), rrotate(y, 19), rshift(y, 10))
        w[t] = (w[t - 16] + s0 + w[t - 7] + s1) % MOD32
    end
    local a, b, c, d, e, f, g, h = H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8]
    for t = 0, 63 do
        local s1 = bxor(rrotate(e, 6), rrotate(e, 11), rrotate(e, 25))
        local ch = bxor(band(e, f), band(bnot(e), g))
        local t1 = h + s1 + ch + K256[t + 1] + w[t]
        local s0 = bxor(rrotate(a, 2), rrotate(a, 13), rrotate(a, 22))
        local maj = bxor(band(a, b), band(a, c), band(b, c))
        h, g, f, e = g, f, e, (d + t1) % MOD32
        d, c, b, a = c, b, a, (t1 + s0 + maj) % MOD32
    end
    H[1], H[2], H[3], H[4] = (H[1] + a) % MOD32, (H[2] + b) % MOD32, (H[3] + c) % MOD32, (H[4] + d) % MOD32
    H[5], H[6], H[7], H[8] = (H[5] + e) % MOD32, (H[6] + f) % MOD32, (H[7] + g) % MOD32, (H[8] + h) % MOD32
end

-- Finishes a hash whose state H has already absorbed `processed` bytes (a
-- multiple of 64) and still has to absorb `data`.
local function finish(H, data, processed)
    local len = #data
    local full = floor(len / 64)
    for i = 0, full - 1 do
        compress(H, data, i * 64 + 1)
    end
    local total = processed + len
    local tail = data:sub(full * 64 + 1) .. "\128" .. rep("\0", (55 - total) % 64) .. be64(total * 8)
    for i = 1, #tail, 64 do
        compress(H, tail, i)
    end
    return be32(H[1]) .. be32(H[2]) .. be32(H[3]) .. be32(H[4])
        .. be32(H[5]) .. be32(H[6]) .. be32(H[7]) .. be32(H[8])
end

local function copyState(H)
    return { H[1], H[2], H[3], H[4], H[5], H[6], H[7], H[8] }
end

-- Returns the raw 32 byte SHA-256 digest of data (use toHex for text).
function sha256(data)
    expectString(data, 1, "sha256")
    return finish(copyState(IV256), data, 0)
end

---------------------------------------------------------------------------
-- HMAC-SHA256 (RFC 2104), HKDF (RFC 5869), PBKDF2 (RFC 8018)
---------------------------------------------------------------------------

local function xorPad(key, value)
    return (key:gsub(".", function(c) return char(bxor(byte(c), value)) end))
end

-- Precomputes the states after the inner and outer key blocks, so every
-- further MAC with the same key costs two compressions less.
local function hmacInit(key)
    if #key > 64 then
        key = finish(copyState(IV256), key, 0)
    end
    key = key .. rep("\0", 64 - #key)
    local inner, outer = copyState(IV256), copyState(IV256)
    compress(inner, xorPad(key, 0x36), 1)
    compress(outer, xorPad(key, 0x5c), 1)
    return inner, outer
end

local function hmacWith(inner, outer, data)
    return finish(copyState(outer), finish(copyState(inner), data, 64), 64)
end

-- Returns the raw 32 byte HMAC-SHA256 of data under key.
function hmac(key, data)
    expectString(key, 1, "hmac")
    expectString(data, 2, "hmac")
    local inner, outer = hmacInit(key)
    return hmacWith(inner, outer, data)
end

-- Derives `length` raw bytes (at most 8160) from input keying material.
function hkdf(ikm, salt, info, length)
    expectString(ikm, 1, "hkdf")
    salt, info = salt or "", info or ""
    expectString(salt, 2, "hkdf")
    expectString(info, 3, "hkdf")
    if type(length) ~= "number" or length < 0 or length > 255 * 32 or length % 1 ~= 0 then
        error("bad argument #4 to 'hkdf' (length must be an integer from 0 to 8160)", 2)
    end
    if salt == "" then
        salt = rep("\0", 32)
    end
    local saltInner, saltOuter = hmacInit(salt)
    local inner, outer = hmacInit(hmacWith(saltInner, saltOuter, ikm))
    local okm, t = {}, ""
    for i = 1, ceil(length / 32) do
        t = hmacWith(inner, outer, t .. info .. char(i))
        okm[i] = t
    end
    return concat(okm):sub(1, length)
end

-- Derives `length` raw bytes from a password with PBKDF2-HMAC-SHA256.
function pbkdf2(password, salt, iterations, length)
    expectString(password, 1, "pbkdf2")
    expectString(salt, 2, "pbkdf2")
    if type(iterations) ~= "number" or iterations < 1 or iterations > MAX_ITERATIONS or iterations % 1 ~= 0 then
        error("bad argument #3 to 'pbkdf2' (iterations must be an integer from 1 to " .. MAX_ITERATIONS .. ")", 2)
    end
    length = length or 32
    if type(length) ~= "number" or length < 1 or length > 1024 or length % 1 ~= 0 then
        error("bad argument #4 to 'pbkdf2' (length must be an integer from 1 to 1024)", 2)
    end
    local inner, outer = hmacInit(password)
    local blocks = {}
    for i = 1, ceil(length / 32) do
        local u = hmacWith(inner, outer, salt .. be32(i))
        local t = { byte(u, 1, 32) }
        for _ = 2, iterations do
            u = hmacWith(inner, outer, u)
            for j = 1, 32 do
                t[j] = bxor(t[j], byte(u, j))
            end
        end
        blocks[i] = char(unpack(t))
    end
    return concat(blocks):sub(1, length)
end

---------------------------------------------------------------------------
-- ChaCha20 (RFC 8439)
---------------------------------------------------------------------------

local function quarterRound(x, a, b, c, d)
    x[a] = (x[a] + x[b]) % MOD32
    x[d] = lrotate(bxor(x[d], x[a]), 16)
    x[c] = (x[c] + x[d]) % MOD32
    x[b] = lrotate(bxor(x[b], x[c]), 12)
    x[a] = (x[a] + x[b]) % MOD32
    x[d] = lrotate(bxor(x[d], x[a]), 8)
    x[c] = (x[c] + x[d]) % MOD32
    x[b] = lrotate(bxor(x[b], x[c]), 7)
end

local function chachaBlock(state)
    local x = { unpack(state, 1, 16) }
    for _ = 1, 10 do
        quarterRound(x, 1, 5, 9, 13)
        quarterRound(x, 2, 6, 10, 14)
        quarterRound(x, 3, 7, 11, 15)
        quarterRound(x, 4, 8, 12, 16)
        quarterRound(x, 1, 6, 11, 16)
        quarterRound(x, 2, 7, 12, 13)
        quarterRound(x, 3, 8, 9, 14)
        quarterRound(x, 4, 5, 10, 15)
    end
    for i = 1, 16 do
        x[i] = (x[i] + state[i]) % MOD32
    end
    return x
end

-- Encrypts or decrypts data with a raw 32 byte key and 12 byte nonce, starting
-- at block `counter`. Never reuse a key and nonce pair for different data.
function chacha20(key, nonce, counter, data)
    expectString(key, 1, "chacha20")
    expectString(nonce, 2, "chacha20")
    expectString(data, 4, "chacha20")
    if #key ~= 32 then error("bad argument #1 to 'chacha20' (key must be 32 bytes)", 2) end
    if #nonce ~= 12 then error("bad argument #2 to 'chacha20' (nonce must be 12 bytes)", 2) end
    if type(counter) ~= "number" or counter < 0 or counter % 1 ~= 0
        or counter + ceil(#data / 64) > MOD32 then
        error("bad argument #3 to 'chacha20' (counter out of range)", 2)
    end
    local state = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        le32(key, 1), le32(key, 5), le32(key, 9), le32(key, 13),
        le32(key, 17), le32(key, 21), le32(key, 25), le32(key, 29),
        counter, le32(nonce, 1), le32(nonce, 5), le32(nonce, 9),
    }
    local out = {}
    for offset = 1, #data, 64 do
        local stream = chachaBlock(state)
        local bytes = { byte(data, offset, offset + 63) }
        local n, j = #bytes, 1
        for w = 1, 16 do
            local word = stream[w]
            for _ = 1, 4 do
                if j > n then break end
                bytes[j] = bxor(bytes[j], word % 256)
                word = floor(word / 256)
                j = j + 1
            end
        end
        out[#out + 1] = char(unpack(bytes, 1, n))
        state[13] = state[13] + 1
    end
    return concat(out)
end

---------------------------------------------------------------------------
-- Random bytes: ChaCha20 generator with fast key erasure
---------------------------------------------------------------------------

local generatorKey
local ZERO_NONCE = rep("\0", 12)

-- Returns the seed file's 64 hex characters, or nil if it is missing or damaged.
local function readSeedFile()
    if not (fs and fs.exists and fs.exists(SEED_FILE)) then return nil end
    local ok, content = pcall(function()
        local handle = fs.open(SEED_FILE, "r")
        if not handle then return nil end
        local text = handle.readAll()
        handle.close()
        return text
    end)
    if ok and type(content) == "string" and #content == 64 and not content:find("[^0-9a-f]") then
        return content
    end
    return nil
end

local function writeSeedFile(hex)
    if not (fs and fs.open) then return end
    pcall(function()
        local handle = fs.open(SEED_FILE, "w")
        if handle then
            handle.write(hex)
            handle.close()
        end
    end)
end

-- Most of these values are public or guessable for other players; they only
-- make pools differ. The secret part comes from the timing jitter, table
-- addresses, math.random's startup seed and the seed file.
local function gatherEntropy()
    local pool = {}
    local function add(value)
        pool[#pool + 1] = type(value) == "number" and format("%.17g", value) or tostring(value)
    end
    if os.getComputerID then add(os.getComputerID()) end
    if os.getComputerLabel then add(os.getComputerLabel()) end
    if os.epoch then
        for _, kind in ipairs({ "utc", "ingame", "local", "nano" }) do
            local ok, value = pcall(os.epoch, kind)
            if ok then add(value) end
        end
    end
    add(os.clock())
    if os.time then add(os.time()) end
    if os.day then add(os.day()) end
    add({})
    add(function() end)
    for _ = 1, 4 do add(math.random()) end
    -- Timing jitter: how many loop iterations fit in one clock tick varies with
    -- JIT, garbage collection and server load. Bounded in time (clock ticks can
    -- be ~16 ms on some hosts) and in total iterations (in case the clock does
    -- not move at all).
    if os.epoch then
        local deadline, budget = os.epoch("utc") + 250, 1000000
        for _ = 1, 256 do
            local start, n = os.epoch("utc"), 0
            repeat n = n + 1 until os.epoch("utc") ~= start or n >= budget
            budget = budget - n
            add(n)
            if budget <= 0 or os.epoch("utc") >= deadline then break end
        end
    end
    add(readSeedFile())
    return concat(pool, "|")
end

local function ensureSeeded()
    if generatorKey then return end
    generatorKey = finish(copyState(IV256), gatherEntropy(), 0)
    writeSeedFile(toHex(randomBytes(32)))
end

-- Seeds the random generator now (it otherwise seeds on first use, which takes
-- up to about a quarter of a second). Calling it again does nothing.
function seed()
    ensureSeeded()
end

-- Mixes extra unpredictable data into the generator.
function addEntropy(data)
    expectString(data, 1, "addEntropy")
    ensureSeeded()
    generatorKey = finish(copyState(IV256), generatorKey .. data, 0)
end

-- Returns n random bytes (raw string).
function randomBytes(n)
    if type(n) ~= "number" or n < 0 or n % 1 ~= 0 then
        error("bad argument #1 to 'randomBytes' (non-negative integer expected)", 2)
    end
    ensureSeeded()
    local stream = chacha20(generatorKey, ZERO_NONCE, 0, rep("\0", 32 + n))
    generatorKey = stream:sub(1, 32)
    return stream:sub(33)
end

-- Returns a uniformly distributed random integer from min to max (inclusive),
-- like math.random(min, max) but from the secure generator.
function randomInt(min, max)
    if type(min) ~= "number" or type(max) ~= "number" or min % 1 ~= 0 or max % 1 ~= 0
        or min > max or max - min >= MOD32 then
        error("bad argument to 'randomInt' (integers min <= max with max - min < 2^32 expected)", 2)
    end
    local range = max - min + 1
    local limit = MOD32 - MOD32 % range -- reject values above the last full multiple of range
    while true do
        local a, b, c, d = byte(randomBytes(4), 1, 4)
        local value = ((a * 256 + b) * 256 + c) * 256 + d
        if value < limit then
            return min + value % range
        end
    end
end

-- Returns a new random key as 64 hex characters.
function generateKey()
    return toHex(randomBytes(32))
end

-- Derives a key (64 hex characters) from a password or passphrase. Both sides
-- must use the same salt and iteration count.
function deriveKey(password, salt, iterations)
    expectString(password, 1, "deriveKey")
    expectString(salt, 2, "deriveKey")
    return toHex(pbkdf2(password, salt, iterations or DEFAULT_ITERATIONS, 32))
end

---------------------------------------------------------------------------
-- Authenticated encryption
---------------------------------------------------------------------------

local TOKEN_VERSION = "\1"
local NONCE_SIZE, TAG_SIZE = 12, 32

local function rawKey(key, index, name)
    if type(key) ~= "string" or #key ~= 64 or not fromHex(key) then
        error(format("bad argument #%d to '%s' (key must be 64 hexadecimal characters, see generateKey)", index, name), 3)
    end
    return fromHex(key)
end

local function subkeys(key)
    local inner, outer = hmacInit(key)
    return hmacWith(inner, outer, "xEncrypt v1 encryption"), hmacWith(inner, outer, "xEncrypt v1 authentication")
end

local function authTag(macKey, header, aad, ciphertext)
    return hmac(macKey, header .. be64(#aad) .. aad .. ciphertext)
end

-- Encrypts plaintext with a key from generateKey/deriveKey. `aad` is optional
-- extra data (for example a sender ID) that is authenticated but not
-- encrypted; decrypt needs the same value. Returns a hex string.
function encrypt(key, plaintext, aad)
    local raw = rawKey(key, 1, "encrypt")
    expectString(plaintext, 2, "encrypt")
    aad = aad or ""
    expectString(aad, 3, "encrypt")
    local encKey, macKey = subkeys(raw)
    local header = TOKEN_VERSION .. randomBytes(NONCE_SIZE)
    local ciphertext = chacha20(encKey, header:sub(2), 1, plaintext)
    return toHex(header .. ciphertext .. authTag(macKey, header, aad, ciphertext))
end

-- Returns the plaintext, or nil and a message if the token is malformed, was
-- modified, or was made with another key or aad. Tokens for plaintexts longer
-- than maxLength bytes (default 65536) are rejected before any work is done,
-- so a huge token received over rednet cannot stall the computer.
function decrypt(key, token, aad, maxLength)
    local raw = rawKey(key, 1, "decrypt")
    aad = aad or ""
    expectString(aad, 3, "decrypt")
    maxLength = maxLength or DEFAULT_MAX_LENGTH
    if type(maxLength) ~= "number" or maxLength < 0 then
        error("bad argument #4 to 'decrypt' (non-negative number expected)", 2)
    end
    local overhead = 1 + NONCE_SIZE + TAG_SIZE
    if type(token) ~= "string" or #token < 2 * overhead or #token > 2 * (overhead + maxLength)
        or #token % 2 ~= 0 or token:find("[^0-9a-f]") then
        return nil, "invalid token"
    end
    if token:sub(1, 2) ~= toHex(TOKEN_VERSION) then
        return nil, "unsupported token version"
    end
    local data = fromHex(token)
    local header = data:sub(1, 1 + NONCE_SIZE)
    local ciphertext = data:sub(2 + NONCE_SIZE, -TAG_SIZE - 1)
    local encKey, macKey = subkeys(raw)
    if not constantTimeEquals(data:sub(-TAG_SIZE), authTag(macKey, header, aad, ciphertext)) then
        return nil, "authentication failed"
    end
    return chacha20(encKey, header:sub(2), 1, ciphertext)
end

---------------------------------------------------------------------------
-- Password storage
---------------------------------------------------------------------------

-- Returns a salted PBKDF2 hash to store instead of the password:
-- "pbkdf2-sha256$<iterations>$<salt hex>$<hash hex>".
function hashPassword(password, iterations)
    expectString(password, 1, "hashPassword")
    iterations = iterations or DEFAULT_ITERATIONS
    local salt = randomBytes(16)
    return format("pbkdf2-sha256$%d$%s$%s", iterations, toHex(salt), toHex(pbkdf2(password, salt, iterations, 32)))
end

-- Checks a password against a string from hashPassword. Anything that is not
-- exactly in hashPassword's format (16 byte salt, 32 byte hash) is rejected.
function verifyPassword(password, stored)
    if type(password) ~= "string" or type(stored) ~= "string" then
        return false
    end
    local iterations, saltHex, hashHex = stored:match("^pbkdf2%-sha256%$([1-9]%d*)%$([0-9a-f]+)%$([0-9a-f]+)$")
    iterations = tonumber(iterations)
    if not iterations or iterations > MAX_ITERATIONS or #saltHex ~= 32 or #hashHex ~= 64 then
        return false
    end
    local hash = fromHex(hashHex)
    return constantTimeEquals(pbkdf2(password, fromHex(saltHex), iterations, #hash), hash)
end
