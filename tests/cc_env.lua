-- Minimal emulation of the parts of CC:Tweaked that the APIs in apis/ use, so
-- they can be tested on a desktop Lua (5.1 to 5.4, LuaJIT) through lupa.
--
-- Every simulated computer gets its own environment, its own settings store and
-- its own in-memory files, so two computers can talk to each other in one test.

local cc = {}

local unpack = table.unpack or unpack

---------------------------------------------------------------------------
-- bit32 (CC:Tweaked has it built in; only Lua 5.2 does on the desktop)
---------------------------------------------------------------------------

local function installBit32()
    if bit32 then return "native" end
    local MOD = 4294967296
    if math.type then
        -- Lua 5.3+: native integer operators, hidden from 5.1 parsers by load().
        bit32 = assert(load([[
            local MOD = 4294967296
            local function n(x) x = x % MOD; return math.tointeger(x) or math.floor(x) end
            local M = {}
            function M.band(...) local r = 0xFFFFFFFF for i = 1, select("#", ...) do r = r & n(select(i, ...)) end return r end
            function M.bor(...) local r = 0 for i = 1, select("#", ...) do r = r | n(select(i, ...)) end return r end
            function M.bxor(...) local r = 0 for i = 1, select("#", ...) do r = r ~ n(select(i, ...)) end return r end
            function M.bnot(x) return (~n(x)) & 0xFFFFFFFF end
            function M.lshift(x, d) if d >= 32 or d <= -32 then return 0 end if d < 0 then return M.rshift(x, -d) end return (n(x) << d) & 0xFFFFFFFF end
            function M.rshift(x, d) if d >= 32 or d <= -32 then return 0 end if d < 0 then return M.lshift(x, -d) end return n(x) >> d end
            function M.lrotate(x, d) d = d % 32 x = n(x) return ((x << d) | (x >> (32 - d))) & 0xFFFFFFFF end
            function M.rrotate(x, d) return M.lrotate(x, -d) end
            function M.btest(...) return M.band(...) ~= 0 end
            return M
        ]], "bit32-polyfill", "t", { math = math, select = select }))()
        return "polyfill-5.3"
    end
    if bit then
        -- LuaJIT: results are signed 32 bit, bit32 returns unsigned.
        local b = bit
        local function u(x) return x % MOD end
        bit32 = {
            band = function(...) return u(b.band(...)) end,
            bor = function(...) return u(b.bor(...)) end,
            bxor = function(...) return u(b.bxor(...)) end,
            bnot = function(x) return u(b.bnot(x)) end,
            lshift = function(x, d) if d >= 32 then return 0 end return u(b.lshift(x, d)) end,
            rshift = function(x, d) if d >= 32 then return 0 end return u(b.rshift(x, d)) end,
            lrotate = function(x, d) return u(b.rol(x, d)) end,
            rrotate = function(x, d) return u(b.ror(x, d)) end,
        }
        bit32.btest = function(...) return bit32.band(...) ~= 0 end
        return "polyfill-luajit"
    end
    -- Plain Lua 5.1: byte-wise lookup tables.
    local XOR, AND = {}, {}
    for a = 0, 255 do
        for c = 0, 255 do
            local x, y, bitv, ra, rb = a, c, 1, 0, 0
            for _ = 1, 8 do
                local p, q = x % 2, y % 2
                if p ~= q then ra = ra + bitv end
                if p == 1 and q == 1 then rb = rb + bitv end
                x, y, bitv = (x - p) / 2, (y - q) / 2, bitv * 2
            end
            XOR[a * 256 + c], AND[a * 256 + c] = ra, rb
        end
    end
    local function op2(tbl, x, y)
        x, y = x % MOD, y % MOD
        local r, m = 0, 1
        for _ = 1, 4 do
            local p, q = x % 256, y % 256
            r = r + tbl[p * 256 + q] * m
            x, y, m = (x - p) / 256, (y - q) / 256, m * 256
        end
        return r
    end
    local function fold(tbl, init, ...)
        local r = init
        for i = 1, select("#", ...) do r = op2(tbl, r, select(i, ...)) end
        return r
    end
    local M = {}
    function M.band(...) return fold(AND, 0xFFFFFFFF, ...) end
    function M.bxor(...) return fold(XOR, 0, ...) end
    function M.bnot(x) return 0xFFFFFFFF - x % MOD end
    function M.bor(...)
        local r = 0
        for i = 1, select("#", ...) do
            local v = select(i, ...) % MOD
            r = op2(XOR, r, v) + op2(AND, r, v)
        end
        return r
    end
    function M.lshift(x, d)
        if d >= 32 or d <= -32 then return 0 end
        if d < 0 then return M.rshift(x, -d) end
        return (x % MOD) * 2 ^ d % MOD
    end
    function M.rshift(x, d)
        if d >= 32 or d <= -32 then return 0 end
        if d < 0 then return M.lshift(x, -d) end
        return math.floor((x % MOD) / 2 ^ d)
    end
    function M.lrotate(x, d)
        d = d % 32
        x = x % MOD
        return M.lshift(x, d) + M.rshift(x, 32 - d)
    end
    function M.rrotate(x, d) return M.lrotate(x, -d) end
    function M.btest(...) return M.band(...) ~= 0 end
    bit32 = M
    return "polyfill-5.1"
end

cc.bit32Mode = installBit32()

---------------------------------------------------------------------------
-- textutils.serialize / unserialize (enough for settings files)
---------------------------------------------------------------------------

local function loadWithEnv(src, name, env)
    if setfenv and loadstring then
        local fn, err = loadstring(src, name)
        if not fn then return nil, err end
        setfenv(fn, env)
        return fn
    end
    return load(src, name, "t", env)
end
cc.loadWithEnv = loadWithEnv

local function serialize(value, seen)
    local t = type(value)
    if t == "string" then
        return string.format("%q", value)
    elseif t == "number" then
        if value ~= value then return "0/0" end
        if value == math.huge then return "1/0" end
        if value == -math.huge then return "-1/0" end
        if value == math.floor(value) and math.abs(value) < 2 ^ 53 then
            return string.format("%d", value)
        end
        return string.format("%.17g", value)
    elseif t == "boolean" or t == "nil" then
        return tostring(value)
    elseif t == "table" then
        seen = seen or {}
        if seen[value] then error("Cannot serialize table with recursive entries", 0) end
        seen[value] = true
        local parts = {}
        local n = #value
        for i = 1, n do parts[#parts + 1] = serialize(value[i], seen) end
        local keys = {}
        for k in pairs(value) do
            if not (type(k) == "number" and k >= 1 and k <= n and k == math.floor(k)) then
                keys[#keys + 1] = k
            end
        end
        table.sort(keys, function(a, b) return tostring(a) < tostring(b) end)
        for _, k in ipairs(keys) do
            parts[#parts + 1] = "[" .. serialize(k, seen) .. "]=" .. serialize(value[k], seen)
        end
        seen[value] = nil
        return "{" .. table.concat(parts, ",") .. "}"
    end
    error("Cannot serialize type " .. t, 0)
end

local function unserialize(s)
    local fn = loadWithEnv("return " .. s, "unserialize", {})
    if not fn then return nil end
    local ok, result = pcall(fn)
    if ok then return result end
    return nil
end

cc.serialize, cc.unserialize = serialize, unserialize

local function deepCopy(v)
    if type(v) ~= "table" then return v end
    local r = {}
    for k, x in pairs(v) do r[k] = deepCopy(x) end
    return r
end
cc.deepCopy = deepCopy

---------------------------------------------------------------------------
-- Computers
---------------------------------------------------------------------------

local Computer = {}
Computer.__index = Computer

-- opts: clock (number, os.clock() value), epoch (number, os.epoch base in ms),
-- echo (boolean, also print to stdout)
function cc.newComputer(id, opts)
    opts = opts or {}
    local self = setmetatable({
        id = id,
        files = {},
        output = {},
        settingsValues = {},
        clockValue = opts.clock or 0.05,
        epochValue = opts.epoch or 1700000000000,
        echo = opts.echo,
    }, Computer)

    -- Only what a CC:Tweaked computer's _G offers (the Lua base library and the
    -- CC APIs emulated below), not the host's globals, so an API that uses
    -- something CC lacks (io, require, os.getenv, the test helpers) fails here
    -- as it would in game.
    local env = {}
    for _, name in ipairs({ "assert", "error", "getmetatable", "ipairs", "load", "loadstring", "next",
        "pairs", "pcall", "rawequal", "rawget", "rawlen", "rawset", "select", "setmetatable", "tonumber",
        "tostring", "type", "xpcall", "_VERSION", "string", "table", "math", "coroutine", "utf8" }) do
        env[name] = _G[name]
    end
    env.unpack = table.unpack or unpack
    env._G = env
    self.env = env

    local function out(...)
        local parts = {}
        for i = 1, select("#", ...) do parts[i] = tostring((select(i, ...))) end
        local line = table.concat(parts, "\t")
        self.output[#self.output + 1] = line
        if self.echo then print("[" .. id .. "] " .. line) end
    end
    env.print = out
    env.printError = out

    -- os: the CC functions (and os.date); none of the host's os.remove,
    -- os.getenv, os.exit and so on, which CC does not have.
    local osT = { date = os.date }
    osT.getComputerID = function() return self.id end
    osT.computerID = osT.getComputerID
    osT.getComputerLabel = function() return nil end
    osT.clock = function() return self.clockValue end
    -- CC:Tweaked accepts only these kinds (any case); "nano" exists only in
    -- CraftOS-PC.
    osT.epoch = function(kind)
        kind = string.lower(kind or "ingame")
        if kind == "utc" or kind == "local" then
            self.epochValue = self.epochValue + 1
            return self.epochValue
        elseif kind == "ingame" then
            return 86400000
        end
        error("Unsupported operation", 2)
    end
    osT.time = function() return 6.0 end
    osT.day = function() return 1 end
    osT.queueEvent = function() end
    osT.pullEvent = function() return "dummy" end
    osT.loadAPI = function(path) return self:loadAPI(path) end
    env.os = osT

    env.textutils = { serialize = serialize, unserialize = unserialize, serialise = serialize, unserialise = unserialize }

    -- fs: flat in-memory files (no directories), shared with settings.load/save.
    local files = self.files
    local function norm(path) return (tostring(path):gsub("^/+", "")) end
    local fsT = {}
    function fsT.combine(a, b)
        local joined = (a == "" and b) or (b == "" and a) or (a .. "/" .. b)
        return (norm(joined):gsub("/+$", ""))
    end
    function fsT.getDir(path) return norm(path):match("^(.*)/[^/]*$") or "" end
    function fsT.getName(path) return norm(path):match("([^/]*)$") end
    function fsT.exists(path) return files[norm(path)] ~= nil end
    function fsT.isDir() return false end
    function fsT.delete(path) files[norm(path)] = nil end
    function fsT.list()
        local r = {}
        for k in pairs(files) do r[#r + 1] = k end
        table.sort(r)
        return r
    end
    function fsT.open(path, mode)
        path = norm(path)
        if self.readOnly and mode:sub(1, 1) ~= "r" then return nil, "Access denied" end
        if mode == "r" or mode == "rb" then
            local content = files[path]
            if content == nil then return nil, "/" .. path .. ": No such file" end
            local pos = 1
            return {
                readAll = function() local r = content:sub(pos) pos = #content + 1 return r end,
                readLine = function()
                    if pos > #content then return nil end
                    local s, e = content:find("\n", pos, true)
                    local line = content:sub(pos, (s or #content + 1) - 1)
                    pos = (e or #content) + 1
                    return line
                end,
                close = function() end,
            }
        elseif mode == "w" or mode == "wb" or mode == "a" or mode == "ab" then
            local parts = { (mode:sub(1, 1) == "a" and files[path]) or "" }
            files[path] = parts[1]
            return {
                write = function(s) parts[#parts + 1] = tostring(s) end,
                writeLine = function(s) parts[#parts + 1] = tostring(s) .. "\n" end,
                flush = function() files[path] = table.concat(parts) end,
                close = function() files[path] = table.concat(parts) end,
            }
        end
        error("Unsupported mode " .. tostring(mode), 2)
    end
    env.fs = fsT
    env.bit32 = bit32

    -- settings, following CC:Tweaked's settings.lua semantics.
    local values = self.settingsValues
    local function reserialize(v)
        if type(v) ~= "table" then return v end
        return unserialize(serialize(v))
    end
    local settings = {}
    function settings.set(name, value)
        if type(name) ~= "string" then error("bad argument #1 (string expected, got " .. type(name) .. ")", 2) end
        local t = type(value)
        if t ~= "number" and t ~= "string" and t ~= "boolean" and t ~= "table" then
            error("bad argument #2 (number, string, boolean or table expected, got " .. t .. ")", 2)
        end
        values[name] = reserialize(value)
    end
    function settings.get(name, default)
        if type(name) ~= "string" then error("bad argument #1 (string expected, got " .. type(name) .. ")", 2) end
        local r = values[name]
        if r ~= nil then return deepCopy(r) end
        return default
    end
    function settings.unset(name) values[name] = nil end
    function settings.clear() for k in pairs(values) do values[k] = nil end end
    function settings.getNames()
        local r = {}
        for k in pairs(values) do r[#r + 1] = k end
        table.sort(r)
        return r
    end
    function settings.load(path)
        local handle = fsT.open(path or ".settings", "r")
        if not handle then return false end
        local content = handle.readAll()
        handle.close()
        local t = unserialize(content)
        if type(t) ~= "table" then return false end
        for k, v in pairs(t) do
            local tv = type(v)
            if type(k) == "string" and (tv == "string" or tv == "number" or tv == "boolean" or tv == "table") then
                values[k] = reserialize(v)
            end
        end
        return true
    end
    function settings.save(path)
        local handle = fsT.open(path or ".settings", "w")
        if not handle then return false end
        handle.write(serialize(values))
        handle.close()
        return true
    end
    env.settings = settings
    self.loadedAPIs = {}
    return self
end

-- Emulates os.loadAPI: the file runs in a fresh environment whose globals become
-- the API table, published under the file name (without ".lua").
function Computer:loadAPI(path)
    local name = path:match("([^/\\]+)$")
    if name:sub(-4) == ".lua" then name = name:sub(1, -5) end
    local fh = assert(io.open(cc.root .. "/" .. path, "rb"))
    local src = fh:read("*a")
    fh:close()
    local apiEnv = setmetatable({}, { __index = self.env })
    local fn, err = loadWithEnv(src, "@" .. path, apiEnv)
    if not fn then error("Failed to load API " .. name .. " due to " .. tostring(err), 2) end
    local ok, perr = pcall(fn)
    if not ok then error("Failed to load API " .. name .. " due to " .. tostring(perr), 2) end
    local api = {}
    for k, v in pairs(apiEnv) do
        if k ~= "_ENV" then api[k] = v end
    end
    self.env[name] = api
    self.loadedAPIs[name] = api
    return api
end

-- Runs a program file from the repository on this computer, as the shell would.
function Computer:runProgram(path)
    local fh = assert(io.open(cc.root .. "/" .. path, "rb"))
    local src = fh:read("*a")
    fh:close()
    local env = self.env
    env.shell = env.shell or { getRunningProgram = function() return path end }
    env.sleep = env.sleep or function() end
    local fn = assert(loadWithEnv(src, "@" .. path, setmetatable({}, { __index = env })))
    return fn()
end

function Computer:setClock(v) self.clockValue = v end
function Computer:lastOutput() return self.output[#self.output] end
function Computer:clearOutput() for i = #self.output, 1, -1 do self.output[i] = nil end end

return cc
