lEncrypt_VERSION = "2.0"
local character_Space_Table = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "!", "@", "#", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", " "}
function genKey()
    local key = math.random(1000, 9999)
    settings.set("key", key)
    settings.save(".settings")
    return key
end
function encrypt(datastring)
    settings.load(".settings")
    local key = settings.get("key")
    if (key == false) then
        print("no encryption key")
        return
    end
    local a = key
    local b = tonumber(datastring)
    local c = a*b
    return c
end
function encode(datastring)
    for index, char in pairs(character_Space_Table) do
        datastring = datastring:gsub(char, ":"..tostring(encrypt(index))..";")
    end
    return datastring
end
function decrypt(datastring, senderid)
    settings.load(".settings")
    local key = settings.get(tostring(senderid))
    if (key == false) then
        print("sender not registered")
        return false
    end
    local a = tonumber(datastring)
    local b = key
    local c = a/b
    return c
end
function decode(datastring, senderid)
    settings.load(".settings")
    local key = settings.get(tostring(senderid))
    if (key == false) then
        print("sender not registered")
        return false
    else
        local result = {}
        for match in (datastring):gmatch(":.-;") do
            local a = match:gsub(":", "")
            local b = a:gsub(";", "")
            local table_input = decrypt(b, senderid)
            table.insert(result, table_input)
        end
        datastring = ""
        for _, entry in pairs(result) do
            if (entry ~= nil and entry ~= "") then
                datastring = datastring..":"..entry..";"
            end
        end
        for index, char in pairs(character_Space_Table) do
            datastring = datastring:gsub(":"..index..";", char)
        end
        return datastring
    end
end