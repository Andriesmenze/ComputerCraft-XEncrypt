-- Tiny test framework used by the test_*.lua files (see run_tests.py).

local T = { passed = 0, failed = 0, skipped = 0, failures = {}, current = nil }

local function repr(v, depth)
    depth = depth or 0
    local t = type(v)
    if t == "string" then
        -- ASCII only, so binary values survive the trip back to Python.
        return '"' .. v:gsub('[%c"\\\128-\255]', function(c) return string.format("\\%03d", c:byte()) end) .. '"'
    elseif t == "table" then
        if depth > 3 then return "{...}" end
        local parts, n = {}, 0
        for k, x in pairs(v) do
            n = n + 1
            if n > 20 then parts[#parts + 1] = "..." break end
            parts[#parts + 1] = "[" .. repr(k, depth + 1) .. "]=" .. repr(x, depth + 1)
        end
        return "{" .. table.concat(parts, ", ") .. "}"
    end
    return tostring(v)
end
T.repr = repr

local function deepEqual(a, b)
    if type(a) ~= type(b) then return false end
    if type(a) ~= "table" then return a == b end
    for k, v in pairs(a) do
        if not deepEqual(v, b[k]) then return false end
    end
    for k in pairs(b) do
        if a[k] == nil then return false end
    end
    return true
end
T.deepEqual = deepEqual

function T.test(name, fn)
    T.current = name
    local ok, err = xpcall(fn, function(e)
        if type(e) == "table" and e.skip then return e end
        return debug.traceback(tostring(e), 2)
    end)
    if ok then
        T.passed = T.passed + 1
    elseif type(err) == "table" and err.skip then
        T.skipped = T.skipped + 1
    else
        T.failed = T.failed + 1
        T.failures[#T.failures + 1] = name .. ": " .. tostring(err)
    end
    T.current = nil
end

function T.skip(reason)
    error({ skip = true, reason = reason }, 0)
end

function T.eq(actual, expected, msg)
    if not deepEqual(actual, expected) then
        error((msg and (msg .. ": ") or "") .. "expected " .. repr(expected) .. ", got " .. repr(actual), 2)
    end
end

function T.neq(actual, unexpected, msg)
    if deepEqual(actual, unexpected) then
        error((msg and (msg .. ": ") or "") .. "did not expect " .. repr(unexpected), 2)
    end
end

function T.ok(v, msg)
    if not v then error(msg or "expected a truthy value", 2) end
    return v
end

function T.raises(fn, pattern)
    local ok, err = pcall(fn)
    if ok then error("expected an error" .. (pattern and (" matching " .. pattern) or ""), 2) end
    if pattern and not tostring(err):find(pattern) then
        error("error " .. repr(tostring(err)) .. " does not match " .. repr(pattern), 2)
    end
    return err
end

function T.summary()
    return T.passed, T.failed, T.skipped, table.concat(T.failures, "\n\n")
end

test, eq, neq, ok, raises, skip = T.test, T.eq, T.neq, T.ok, T.raises, T.skip

return T
