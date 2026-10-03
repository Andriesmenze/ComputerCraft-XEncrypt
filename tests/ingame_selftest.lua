-- Self-test to run on a real CC:Tweaked computer (or CraftOS-PC), where the
-- desktop test suite cannot reach: checks the official test vectors on Cobalt
-- and measures how long the slow operations take there.
--
--   Copy the repository to a disk, then run: disk/tests/ingame_selftest.lua

local root = fs.getDir(fs.getDir(shell.getRunningProgram()))
os.loadAPI(fs.combine(root, "apis/xEncrypt.lua"))
os.loadAPI(fs.combine(root, "apis/Unicode.lua"))
local X, U = xEncrypt, Unicode

local passed, failed = 0, 0
local function check(name, condition)
    if condition then
        passed = passed + 1
    else
        failed = failed + 1
        printError("FAIL " .. name)
    end
    sleep(0) -- yield between checks
end

local function timed(fn)
    local start = os.epoch("utc")
    fn()
    return os.epoch("utc") - start
end

print("xEncrypt " .. X.xEncrypt_VERSION .. " self-test")

local seedTime = timed(function() X.seed() end)

check("sha256", X.toHex(X.sha256("abc")) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
check("hmac", X.toHex(X.hmac("Jefe", "what do ya want for nothing?"))
    == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
check("pbkdf2", X.toHex(X.pbkdf2("password", "salt", 2, 32))
    == "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
local key32 = X.fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
check("chacha20", X.toHex(X.chacha20(key32, X.fromHex("000000090000004a00000000"), 1, string.rep("\0", 16)))
    == "10f1e7e4d13b5915500fdd1fa32071c4")

local key = X.generateKey()
local token = X.encrypt(key, "hello", "aad")
check("encrypt/decrypt", X.decrypt(key, token, "aad") == "hello")
check("tamper detection", X.decrypt(key, token:sub(1, -2) .. (token:sub(-1) == "0" and "1" or "0"), "aad") == nil)
check("wrong aad", X.decrypt(key, token, "other") == nil)
check("unicode", U.transcodeUnicodeString(U.transcodeUTF8String("a\\b\n")) == "a\\b\n")

local hashTime, stored
hashTime = timed(function() stored = X.hashPassword("pw") end)
check("password", X.verifyPassword("pw", stored) and not X.verifyPassword("px", stored))

local data = string.rep("x", 10000)
local encryptTime = timed(function() X.encrypt(key, data) end)

print(("%d passed, %d failed"):format(passed, failed))
print(("seeding:            %5d ms"):format(seedTime))
print(("hashPassword:       %5d ms (1000 iterations)"):format(hashTime))
print(("encrypt 10000 bytes: %4d ms"):format(encryptTime))
