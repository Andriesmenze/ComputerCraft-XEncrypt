# Building a rednet protocol with xEncrypt

xEncrypt makes a single message confidential and tamper-proof. A protocol built on it still has to get keys to the right computers, reject replays, and survive hostile traffic. This guide lists what to do for a typical client/server program, such as a mail or banking server. Each point comes from a problem found in a real CC program.

## Threat model

Any player can place a computer with a wireless modem in range, or with an ender modem anywhere in the world (any dimension), and run their own Lua on it. That computer can:

- read every rednet message (rednet is broadcast on modem channels);
- send messages with a fake sender ID: `modem.transmit` lets it choose the reply channel, and the `nSender` field in a rednet message, which `rednet.receive` reports as the sender;
- record messages and send them again later;
- send huge or malformed messages, or flood a computer: a computer's event queue holds 256 events, and the rest are dropped.

It cannot read the disk of a computer it cannot physically reach. A player who can reach one can hold Ctrl+T to stop the running program and use the shell (`edit .settings` shows the keys), or hold Ctrl+R with a disk drive attached and boot their own code from the disk. On every server and client:

- put `os.pullEvent = os.pullEventRaw` at the top of the program and wrap its main loop in `pcall`, rebooting on errors, so neither Ctrl+T nor a crash leaves a shell;
- turn off disk startup: `settings.set("shell.allow_disk_startup", false)` and `settings.save()`;
- keep computers that hold keys where other players cannot reach them.

## Keys

- **One key per client.** The server stores `settings.set("myapp.client." .. id, key)`. Never use one key for the whole network: one stolen client key would then expose everyone.
- **Getting the first key across.** The key must not travel in the clear. Two simple options:
  - A floppy disk carried from the server to the client.
  - A one-time registration code. The admin generates a random code on the server, at least 12 characters from a 32-character alphabet (60 bits), with `xEncrypt.randomInt`. The user types it on the client. Both sides compute `xEncrypt.deriveKey(code, "myapp register " .. serverId, ITERATIONS)`. The client generates its long-term key with `generateKey()` and sends it encrypted under that derived key.
    - Bind the code to the client's computer ID. The admin enters the ID when generating the code, and the server rejects any other ID.
    - Let a code expire after a few minutes and after one use.
    - Never let a registration overwrite an existing client without the admin's say-so.
    - Treat the code like a password, even after it was used: anyone who recorded the registration message and later learns the code can recover the client's key.
    - Pin the iteration count as a constant in your program (xEncrypt accepts 1 to 5000). If client and server use different values, they derive different keys.
    - Show the code and the server ID on the admin screen; the client needs both (the ID for the salt and as the address to send to). Use an alphabet without look-alikes (no 0/O or 1/I/L), and normalise the typed code the same way on both sides before `deriveKey` (uppercase, remove spaces and dashes). A wrong code fails silently, so a small difference would look like a server that does not answer.
- **Entropy.** A fresh computer has little entropy. Before generating secrets (the registration code on the server, the long-term key on the client), mix in key-press timings on that computer, for example while the admin types in the admin menu or the user types the code. `read()` keeps the key events to itself, so collect them alongside it:

  ```lua
  local code
  parallel.waitForAny(
      function() code = read() end,
      function()
          while true do
              os.pullEvent("char")
              xEncrypt.addEntropy(tostring(os.epoch("utc")))
          end
      end)
  ```

  Never feed data received over the network to `addEntropy`: it is public, and the sender chooses its type and size.

## Messages

- **Use the AAD.** Encrypt requests with aad `"myapp request " .. clientId` and responses with `"myapp response " .. clientId`. A request then cannot be replayed as a response or passed off as coming from another client.
- **Never run code from the network.** Do not call `textutils.unserialize`, `load` or `loadstring` on anything received, not even after `decrypt` succeeds. `textutils.unserialize` runs its input as Lua, so a registered but malicious client could stall your server for about 7 seconds per message (unserialize's own `pcall` catches the timeout), allocate gigabytes with `string.rep`, or trigger the hard abort that shuts the computer down. Encode messages as JSON with `textutils.serializeJSON` / `textutils.unserializeJSON` (wrapped in `pcall`), or as a fixed format you parse yourself. Then check every field's type, length and allowed values. JSON only round-trips ASCII: `serializeJSON` writes bytes 0x80-0xFF as `\u00XX` and `unserializeJSON` turns those into UTF-8, so text typed in game (`"caf\233"`) comes back changed. Hex-encode (`xEncrypt.toHex`) any field that can hold such bytes, or reject non-ASCII fields.
- **Replays.** Every request carries a random ID (`xEncrypt.toHex(xEncrypt.randomBytes(16))`) and `os.epoch("utc")`. The server rejects requests more than about 60 seconds old and IDs it has seen in the last few minutes. All computers in one world share the server's clock. The seen IDs can live in memory if the server also records `os.epoch("utc")` when it starts and rejects any request stamped earlier, so a request recorded just before a reboot or chunk reload cannot be replayed after it. The response echoes the request ID, and the client accepts only a response with its own ID.
- **Size limits first.** Check the envelope before any crypto: it must be a table, have the expected fields and types, and `#box` must be below your maximum. Pass a `maxLength` to `decrypt` that fits your largest message. Hex decoding and MAC checks cost time in proportion to size, and a computer that runs about 7 seconds without yielding is stopped.
- **Fail silently.** Do not answer anything that fails a check before `decrypt` succeeds: wrong format, unknown client, bad tag. Replies go to a sender ID that an attacker can fake. Error replies to unauthenticated messages can be aimed at another server, or at the server itself, to start an endless loop.
- **Reply targets.** Send replies with `rednet.send(id, ...)` to the authenticated client's registered ID, not to a broadcast.
- **Client timeouts.** Wait for an answer against one fixed deadline, not with a fresh timeout per received message:

  ```lua
  local deadline = os.clock() + 5
  while true do
      local remaining = deadline - os.clock()
      if remaining <= 0 then return nil, "server not responding" end
      local sender, msg = rednet.receive("myapp", remaining)
      -- check, decrypt, match the request ID; ignore anything else and keep waiting
  end
  ```

  Otherwise anyone can keep the client waiting forever by sending junk.

## Server

- **No string commands.** Dispatch on a fixed table of operations (`login`, `send`, ...). Never build Lua source from request fields.
- **Authorize every operation.** Logging in should produce server-side state, such as `loggedIn[clientId] = {user = ..., lastSeen = ...}`. Every later operation uses that user, never a user name sent by the client. Clear it on logout, password change, revoke and re-registration.
- **Passwords.** Store `xEncrypt.hashPassword(password)` and check with `verifyPassword`. Require the old password to set a new one. Throttle failed logins per client, because every check costs a PBKDF2 run on the server. A password change verifies the old hash and computes a new one, twice the cost; with more than the default 1000 iterations, split it over two events (verify, queue a private event, hash on the next one). An unknown user name returns `false` at once while a real one takes a PBKDF2 run, so response times reveal which names exist; if that matters, check unknown names against a dummy hash made once with `hashPassword` and give the same error.
- **File names.** Never use names, subjects or other request text in file paths (`../startup.lua`). Validate user names against a strict pattern such as `^[a-z0-9_-]+$`, lowercase them (servers on Windows or macOS have case-insensitive disks), and name stored files yourself, for example `os.epoch("utc") .. "-" .. xEncrypt.toHex(xEncrypt.randomBytes(4))`.
- **Disk space.** A CC computer has about 1 MB. Limit messages per user and check `fs.getFreeSpace` before writing, so one user cannot fill the disk.
- **Separate namespaces.** Prefix every settings key (`myapp.user.<name>`, `myapp.client.<id>`), so a user called `key` cannot overwrite another setting.
- **Errors.** Wrap the handling of each message in `pcall`. Log errors to a file, not to the screen.

## Known limits

- Anyone within wireless range, or anyone anywhere with an ender modem, can jam wireless rednet by flooding it. Encryption cannot prevent that. Wired modem networks only reach the computers on their cables.
- A shared, public terminal is within reach of every player, so even with the measures from the threat model treat its key as exposed.
- The client deadline loop relies on one timer event. When a flood fills the computer's 256-event queue, that timer can be dropped, and `rednet.receive` then waits until a matching message arrives. A client that must never hang can pull events itself, compare `os.clock()` with the deadline on every event, and start a new timer for the remaining time after each one.
- Without a key exchange such as Diffie-Hellman there is no forward secrecy: if a client key leaks, recorded traffic of that client can be decrypted.
