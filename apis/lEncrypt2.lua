lEncrypt2_VERSION = "0.1a"

-- Seed math.random for better randomness
math.randomseed(os.getComputerID() * os.clock())

local characterSpaceTable = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "!", "@", "#", ",", ".", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", " ", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "+"}

local reverseCharacterSpaceTable = {}
for index, character in pairs(characterSpaceTable) do
    reverseCharacterSpaceTable[character] = index
end

function tablesMatch(a, b)
    return table.concat(a) == table.concat(b)
end

function tableShuffle(inputTable)
    local shuffledTable = {}
    for i = 1, #inputTable do
        shuffledTable[i] = inputTable[i]
    end
    for i = #shuffledTable, 2, -1 do
        local j = math.random(i)
        shuffledTable[i], shuffledTable[j] = shuffledTable[j], shuffledTable[i]
    end
    while tablesMatch(inputTable, shuffledTable) do
        for i = #shuffledTable, 2, -1 do
            local j = math.random(i)
            shuffledTable[i], shuffledTable[j] = shuffledTable[j], shuffledTable[i]
        end
    end
    return shuffledTable
end

function getCharacterIndex(inputCharacter)
    return reverseCharacterSpaceTable[inputCharacter] or nil
end

function doubleDigitCheck(numInput)
    return string.format("%02d", numInput)
end

function genHostDisks()
    local disks = {}
    for i = 1, 10 do
        table.insert(disks, tableShuffle(characterSpaceTable))
    end
    return disks
end

function improvedEncrypt(input)
    settings.load(".settings")
    local disks = settings.get("Disks")
    local output = ""
    local currentDiskSelecter = 1

    for character = 1, string.len(input) do
        local currentDisk = disks[currentDiskSelecter]
        local charIndex = getCharacterIndex(string.sub(input, character, character))
        if charIndex then
            -- Rotate character index within the disk based on currentDiskSelecter
            local newIndex = (charIndex + currentDiskSelecter - 1) % #currentDisk
            if newIndex == 0 then
                newIndex = #currentDisk
            end
            output = output .. currentDisk[newIndex]
        else
            return nil, "Character not found in character space table"
        end
        currentDiskSelecter = (currentDiskSelecter % 10) + 1
    end

    return output
end

function improvedDecrypt(input, senderid)
    settings.load(".settings")
    local senderRecord = settings.get(tostring(senderid))
    if not senderRecord then
        return nil, "Sender not registered"
    end
    local senderDisks = senderRecord[2]
    local output = ""
    local currentDiskSelecter = 1

    for character = 1, string.len(input) do
        local currentDisk = senderDisks[currentDiskSelecter]
        local charIndex = getCharacterIndex(string.sub(input, character, character))
        if charIndex then
            -- Rotate character index back within the disk based on currentDiskSelecter
            local originalIndex = (charIndex - currentDiskSelecter) % #currentDisk
            if originalIndex <= 0 then
                originalIndex = originalIndex + #currentDisk
            end
            output = output .. currentDisk[originalIndex]
        else
            return nil, "Character not found in character space table"
        end
        currentDiskSelecter = (currentDiskSelecter % 10) + 1
    end

    return output
end

function selfRegisterAtHost()
    settings.load(".settings")
    local cryptSet = settings.get("cryptSet")
    local lEncrypt1key = cryptSet[1]
    local disks = cryptSet[2]
    local compID = os.getComputerID()
    settings.set(tostring(compID), {lEncrypt1key, disks})
    settings.save(".settings")
end

function genCryptSet(currentKey)
    local lEncrypt1key = currentKey or math.random(1000, 9999)
    local disks = genHostDisks()
    local cryptSet = {lEncrypt1key, disks}
    settings.set("cryptSet", cryptSet)
    settings.save(".settings")
end

function genKey()
    local key = math.random(1000, 9999)
    settings.set("key", key)
    settings.save(".settings")
    return key
end

function encrypt(datastring)
    settings.load(".settings")
    local key = settings.get("key")
    if not key then
        print("No encryption key")
        return nil
    end
    local a = key
    local b = tonumber(datastring)
    if not b then
        return nil, "Invalid data string for encryption"
    end
    return a * b
end

function encode(datastring)
    for index, char in pairs(characterSpaceTable) do
        datastring = datastring:gsub(char, ":" .. tostring(encrypt(index)) .. ";")
    end
    return datastring
end

function decrypt(datastring, senderid)
    settings.load(".settings")
    local key = settings.get(tostring(senderid))
    if not key then
        print("Sender not registered")
        return nil
    end
    local a = tonumber(datastring)
    if not a then
        return nil, "Invalid data string for decryption"
    end
    return a / key
end

function decode(datastring, senderid)
    settings.load(".settings")
    local key = settings.get(tostring(senderid))
    if not key then
        print("Sender not registered")
        return nil
    else
        local result = {}
        for match in datastring:gmatch(":(.-);") do
            local table_input = decrypt(match, senderid)
            if table_input then
                table.insert(result, table_input)
            end
        end
        datastring = ""
        for _, entry in pairs(result) do
            datastring = datastring .. ":" .. entry .. ";"
        end
        for index, char in pairs(characterSpaceTable) do
            datastring = datastring:gsub(":" .. index .. ";", char)
        end
        return datastring
    end
end