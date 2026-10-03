# XEncrypt

Encryption and text encoding APIs for [CC:Tweaked](https://tweaked.cc) (ComputerCraft) computers, in pure Lua.

| File | What it is |
| --- | --- |
| `apis/xEncrypt.lua` | Authenticated encryption (ChaCha20 + HMAC-SHA256), SHA-256, HMAC, HKDF, PBKDF2, password hashing and random keys. |
| `apis/Unicode.lua` | Converts text to and from `U+XXXX` code point notation. |
| `docs/protocol-guide.md` | How to build a client/server protocol over rednet on top of xEncrypt (keys, replays, hostile traffic). |
| `tests/` | Test suite that runs the APIs on desktop Lua against official test vectors and reference implementations. |

The older `lEncrypt` and `lEncrypt2` APIs have been removed because they did not protect anything (see [Migrating from lEncrypt and lEncrypt2](#migrating-from-lencrypt-and-lencrypt2)).

## Installation

Copy `apis/xEncrypt.lua` (and `apis/Unicode.lua` if you need it) to the computer, for example from a floppy disk:

```
copy disk/apis/xEncrypt.lua apis/xEncrypt.lua
```

and load it in your program:

```lua
os.loadAPI("apis/xEncrypt.lua")
```

Use `os.loadAPI`; the file does not support `require`. To update an existing copy, `delete apis/xEncrypt.lua` first: `copy` (and `wget`) refuse to overwrite a file. Without access to a disk, download the file with `wget` from wherever you host it (CC:Tweaked's http API must be enabled).

xEncrypt needs the `bit32` library, which CC:Tweaked provides. It only uses Lua features that CC:Tweaked's Cobalt runtime supports ([Lua 5.2/5.3 features in CC: Tweaked](https://tweaked.cc/reference/feature_compat.html): no integer subtype or bitwise operators), and its source is plain ASCII and everything it stores is hex, so it behaves the same on CC:Tweaked versions before and after 1.109 (which changed how files are read).

## xEncrypt

### Encrypting messages between computers

Both computers need the same key. A key is 64 hexadecimal characters, so it can be stored with `settings`, written to a file or typed in.

```lua
-- Once, on one computer: create a key and get it to the other computer safely
-- (for example on a floppy disk). Never send it over rednet in the clear.
local key = xEncrypt.generateKey()
settings.set("chat.key", key)
settings.save()
```

```lua
-- Sender (computer 5)
peripheral.find("modem", rednet.open)
local key = settings.get("chat.key")
local token = xEncrypt.encrypt(key, "meet at the mine", "chat from 5")
rednet.send(7, token, "chat")
```

```lua
-- Receiver (computer 7)
peripheral.find("modem", rednet.open)
local key = settings.get("chat.key")
local sender, token = rednet.receive("chat")
local message, err = xEncrypt.decrypt(key, token, "chat from " .. sender)
if message then
    print(message)
else
    print("Rejected message: " .. err)
end
```

`encrypt` returns a hex string that is safe to send over rednet, store in settings or write to a text file. The third argument is optional extra data (here the sender ID) that is not encrypted but is checked: `decrypt` only succeeds with the same value, so a captured message cannot be replayed as coming from another computer or another context. Every computer that holds the key can still write messages with any extra data, so give each pair of computers its own key if it matters who sent a message.

`decrypt` returns `nil` and a reason (`"invalid token"`, `"token too long"`, `"unsupported token version"` or `"authentication failed"`) when a token is malformed, longer than allowed (see `maxLength` below; a receiver must pass a larger `maxLength` for plaintexts over 64 KiB), was changed, or was made with another key or extra data. It never returns a partially decrypted or modified message.

### Keys from a passphrase

```lua
local key = xEncrypt.deriveKey("correct horse battery staple", "my-app")
```

Both sides get the same key from the same passphrase and salt (the second argument; use a fixed string per application). Anyone who can guess the passphrase can do the same, so use a long random one.

### Storing passwords

Store a hash instead of the password:

```lua
settings.set("user.alice", xEncrypt.hashPassword(password))   -- "pbkdf2-sha256$1000$<salt>$<hash>"
settings.save()   -- set only changes memory
...
if xEncrypt.verifyPassword(attempt, settings.get("user.alice")) then
    print("Welcome")
end
```

A hash uses 1000 PBKDF2 iterations by default, which takes about 0.7 seconds in game (CC's Cobalt VM; up to about 1.5 s on first use or on a busy server). CraftOS-PC runs C Lua and is 2 to 4 times faster, so time things in game. That slows down guessing over the network, but it is far below what protects password hashes on real servers, so a short password can still be guessed offline by someone who gets hold of the hash. Keep stored hashes on computers other players cannot open, and tell users not to use a password they use anywhere outside the game. You can pass a higher iteration count (up to 5000) as the second argument of `hashPassword`, but the library never yields, so a login server spends that time on every check and handles none of its own events meanwhile: rednet messages, timers and key presses queue up, and anything past 256 queued events is dropped. (CC:Tweaked pauses a busy computer when others want to run, so other computers are only slowed down.) Call `verifyPassword` for network requests inside `pcall` and do no other heavy work in the same event; a password change (verify the old one, hash the new one) costs twice as much.

### API

| Function | Returns |
| --- | --- |
| `generateKey()` | A new random key (64 hex characters). |
| `deriveKey(password, salt [, iterations])` | A key derived with PBKDF2-HMAC-SHA256 (default 1000 iterations). |
| `encrypt(key, plaintext [, aad])` | A token (hex string). |
| `decrypt(key, token [, aad [, maxLength]])` | The plaintext, or `nil` and a reason. Tokens whose plaintext would be longer than `maxLength` bytes (default 65536; a token is 90 + 2 × length hex characters) are rejected before any work. |
| `hashPassword(password [, iterations])` | A salted password hash string. |
| `verifyPassword(password, stored)` | `true` if the password matches the stored hash. |
| `randomBytes(n)` | `n` random bytes. |
| `randomInt(min, max)` | A uniformly distributed integer from `min` to `max`, like `math.random(min, max)` but from the secure generator. Bounds within ±2^53, at most 2^32 values. |
| `addEntropy(data)` | Mixes a string of extra unpredictable local data into the random generator; it is saved to the seed file at the next random draw. |
| `seed()` | Seeds the random generator now instead of on first use (takes about a quarter of a second). |
| `sha256(data)` | 32-byte SHA-256 digest. |
| `hmac(key, data)` | 32-byte HMAC-SHA256. |
| `hkdf(ikm, salt, info, length)` | `length` bytes from HKDF-SHA256; `salt` and `info` may be `nil`. |
| `pbkdf2(password, salt, iterations [, length])` | `length` (default 32, up to 1024) bytes from PBKDF2-HMAC-SHA256. Each 32 bytes of output costs `iterations` HMACs, and `iterations × ceil(length / 32)` may be at most 5000; for more key material, run `hkdf` on a 32-byte result. |
| `chacha20(key, nonce, counter, data)` | ChaCha20 (RFC 8439) with a 32-byte key and 12-byte nonce. |
| `toHex(data)`, `fromHex(hex)` | Hex encoding; `fromHex` returns `nil` for invalid input. |
| `constantTimeEquals(a, b)` | String comparison that does the same work for any two strings of equal length, without stopping at the first difference. A best effort: Lua on the JVM gives no strict constant-time guarantee. |

`sha256`, `hmac`, `hkdf`, `pbkdf2`, `chacha20` and `randomBytes` work on raw byte strings; use `toHex` to print them. Passing a wrong argument type or a malformed key raises an error, except where a value may come from the network: `decrypt` returns `nil, "invalid token"` for a token that is not a string, `verifyPassword` and `constantTimeEquals` return `false` and `fromHex` returns `nil` for non-strings. Convert numbers (a PIN, say) with `tostring` before hashing or verifying.

### How it works

- `encrypt` derives an encryption key and a separate authentication key from your key with HMAC-SHA256, encrypts with ChaCha20 under a random 96-bit nonce, and appends an HMAC-SHA256 tag over the version, nonce, extra data (with its length) and ciphertext (encrypt-then-MAC). `decrypt` checks the tag in constant time before decrypting. Token layout: `version (1 byte) | nonce (12) | ciphertext | tag (32)`, hex encoded. Hex doubles the size, but it survives text-mode files and settings on every CC:Tweaked version and needs no extra module (`cc.base64` only exists since CC:Tweaked 1.119, and only through `require`).
- All primitives are checked against the official test vectors (FIPS 180-4, RFC 4231, RFC 5869, RFC 7914, RFC 8439) and against Python's `hashlib` and OpenSSL on random inputs.

### Limitations

- **Key distribution is up to you.** Encryption only helps if the key reaches the other computer without being overheard. Copy it on a disk, derive it from a strong passphrase on both sides, or let an admin type it in. Anyone who can reach a computer can read the keys stored on it: by holding Ctrl+T to stop the program and using the shell, or by rebooting it from a disk with Ctrl+R. Put `os.pullEvent = os.pullEventRaw` at the top of the program and wrap its main loop in `pcall`, turn off disk startup with `settings.set("shell.allow_disk_startup", false)` and `settings.save()`, and keep key-holding computers out of other players' reach.
- **Replays.** A recorded token decrypts again later. If that matters (logins, commands), put a counter or `os.epoch("utc")` timestamp and a random ID in the message and reject repeats.
- **Randomness.** CC has no secure random source. xEncrypt seeds its generator from clocks, the computer ID, `math.random`, table addresses and timing jitter, and keeps a seed file (`/.xEncrypt.seed`), rewritten at seeding and at the first random draw after `addEntropy`, so entropy accumulates over reboots. Restoring a world backup with an old seed file does not repeat earlier random output (or nonces): computers do not keep their Lua state, they reboot and reseed, and the pool includes the current real-world time and fresh timing jitter. Most of those values can be guessed by other players; the timing jitter, table addresses and the seed file are what keep it unpredictable. Call `xEncrypt.addEntropy(tostring(os.epoch("utc")))` at every key press, especially before generating a long-term key on a freshly installed computer (see the protocol guide for how to do that while `read()` runs). A program that never draws random bytes (decrypt or verify only) can call `xEncrypt.randomBytes(0)` to save the added entropy. Never pass data received over the network: it is public, and the sender picks its size. Use `randomBytes`/`randomInt`, never `math.random`, for anything secret.
- **Speed.** Pure Lua is slow: encrypting 10 KB takes roughly 0.1 to 0.2 s in game (about 30 ms in CraftOS-PC). The library never yields, so keep single calls well under CC's "too long without yielding" limit (`decrypt` caps token size for this reason).
- Message length is not hidden.
- **Who this protects against.** Other players on the server. Not whoever runs the Minecraft server or has access to the world files: they can read every computer's files, keys and seed file. Do not protect real-world secrets with it.

For a client/server program (logins, commands, mail), read [docs/protocol-guide.md](docs/protocol-guide.md): it covers getting keys to clients, replays, size limits and the other things encryption alone does not solve.

## Unicode

```lua
os.loadAPI("apis/Unicode.lua")
Unicode.transcodeUTF8String("Hé")             -- "U+0048U+00E9"
Unicode.transcodeUnicodeString("U+0048U+00E9") -- "H\233" (é in the CC charset)
Unicode.transcodeUnicodeString("U+20AC", true) -- "€" as UTF-8 bytes
```

| Function | Returns |
| --- | --- |
| `transcodeUTF8Character(char)` | `"U+XXXX"` for one character, or `nil` if the input is not exactly one character. |
| `transcodeUnicodeCharacter(code [, asUTF8])` | The character for one code, or `nil` for invalid notation. |
| `transcodeUTF8String(text [, fromCC])` | `"U+XXXX"` for every character. With `fromCC = true` every byte is one character (for text typed in game). |
| `transcodeUnicodeString(codes [, asUTF8])` | The text for every code in the input; other text is skipped and invalid code points become `?`. |

Notation: `U+` (any case) followed by 4 to 6 hex digits, where leading zeros only pad to 4: `U+00E9` and `U+1F600` are valid, `U+0000E9` is not (in a string it reads as `U+0000` followed by the text `E9`). Separate a code like `U+20AC` from hex text that follows it.

Input text is read as UTF-8 where it is valid UTF-8; any other byte is read as the code point with the same value (ISO-8859-1). For bytes 0xA0-0xFF that is the character CC shows; CC's drawing characters 0x80-0x9F become control code points U+0080-U+009F. Output uses the CC charset (one byte per character, `?` above U+00FF) unless `asUTF8` is `true`. A CC string that happens to form valid UTF-8 is read as one UTF-8 character: `"\195\169"`, and also natural in-game text such as `"Spa\223\171"` (sharp s followed by a guillemet). Pass `fromCC = true` for text typed in game or read in text mode.

To pass UTF-8 to or from outside the game unchanged on every CC:Tweaked version, use binary mode: read with `fs.open(path, "rb")` or `http.get(url, headers, true)`, and write `asUTF8` output with `fs.open(path, "wb")`. Before CC:Tweaked 1.109, text-mode reads turn every character above U+00FF into `?`, and text-mode writes store every byte from 0x80 up as two bytes.

## Migrating from lEncrypt and lEncrypt2

lEncrypt and lEncrypt2 were removed because they did not provide any protection and had bugs that broke them outright:

- `encode` multiplied each character's position in a table by a 4-digit key. For almost any message the greatest common divisor of its numbers is the key, so messages revealed their own key and with it the text.
- lEncrypt2's `encode` garbled every input (a `.` in its character table matched every character as a Lua pattern), `improvedEncrypt` always crashed (it read a setting that nothing wrote), and `improvedDecrypt` did not reverse `improvedEncrypt`.
- `decode` silently dropped characters outside the table (digits, most punctuation), so `abc123` and `abc` were the same password.
- `math.randomseed(os.getComputerID() * os.clock())` made the generated keys predictable (always seed 0 on computer 0).

| lEncrypt / lEncrypt2 | xEncrypt |
| --- | --- |
| `genKey()` (4-digit key in setting `key`) | `generateKey()` (store the result yourself) |
| `encode(text)` / `decode(text, senderID)` | `encrypt(key, text, aad)` / `decrypt(key, token, aad)` with the sender's key |
| Storing `encode(password)` | `hashPassword(password)` / `verifyPassword(password, stored)` |
| `genCryptSet`, `improvedEncrypt`, `improvedDecrypt`, `selfRegisterAtHost` | `generateKey`, `encrypt`, `decrypt`; keep one key per peer, for example in `settings.set("myapp.peer." .. id, key)` |

Tokens and stored values from the old APIs cannot be read by xEncrypt. Programs that used them must generate new keys and have users set their passwords again.

## Running the tests

The tests run the APIs on desktop Lua 5.1 to 5.4 and LuaJIT through [lupa](https://pypi.org/project/lupa/), with a small emulation of the CC:Tweaked APIs they use (`tests/cc_env.lua`). Lua 5.2 is closest to CC:Tweaked.

```bash
pip install lupa cryptography
python tests/run_tests.py
```

`--lua lua52` limits the run to one runtime, `-k xEncrypt` to matching test files, and `--heavy` adds slow tests (one million byte SHA-256, 4096-iteration PBKDF2). `cryptography` is needed for the ChaCha20 comparison with OpenSSL and for the checks that tokens made in Lua open in an independent Python implementation and the other way round; without it those three checks are skipped (a known-answer test in the Lua suite still pins the token format). A runtime named with `--lua` that is not available counts as a failure, and a test file that runs longer than `--timeout` CPU seconds (default 600) fails instead of hanging.

`tests/ingame_selftest.lua` checks the test vectors on a real computer and prints how long hashing and encryption take there. Run it in game from a disk with the repository on it (`disk/tests/ingame_selftest.lua`), or on [CraftOS-PC](https://www.craftos-pc.cc), which ships the real CC:Tweaked ROM:

```bash
python tests/run_craftos.py
```

Set `CRAFTOS_PC` to `CraftOS-PC_console.exe` if it is not in `C:\Program Files\CraftOS-PC\`.
