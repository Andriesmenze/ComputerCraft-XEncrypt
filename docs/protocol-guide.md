# Building a rednet protocol with xEncrypt

xEncrypt makes a single message confidential and tamper-proof. A protocol built on it still has to get keys to the right computers, reject replays, and survive hostile traffic. This guide lists what to do for a typical client/server program, such as a mail or banking server. Each point comes from a problem found in a real CC program.

## Threat model

Any player can place a computer with a modem in range and run their own Lua on it. That computer can:

- read every rednet message (rednet is broadcast on modem channels);
- send messages with a fake sender ID: `modem.transmit` lets it choose the reply channel, and the `nSender` field in a rednet message, which `rednet.receive` reports as the sender;
- record messages and send them again later;
- send huge or malformed messages, or flood a computer: a computer's event queue holds 256 events, and the rest are dropped.

It cannot read the disk of a computer it cannot open.

## Keys

- **One key per client.** The server stores `settings.set("myapp.client." .. id, key)`. Never use one key for the whole network: one stolen client key would then expose everyone.
- **Getting the first key across.** The key must not travel in the clear. Two simple options:
  - A floppy disk carried from the server to the client.
  - A one-time registration code. The admin generates a random code on the server, at least 12 characters from a 32-character alphabet (60 bits), with `xEncrypt.randomInt`. The user types it on the client. Both sides compute `xEncrypt.deriveKey(code, "myapp register " .. serverId, ITERATIONS)`. The client generates its long-term key with `generateKey()` and sends it encrypted under that derived key.
    - Bind the code to the client's computer ID. The admin enters the ID when generating the code, and the server rejects any other ID.
    - Let a code expire after a few minutes and after one use.
    - Never let a registration overwrite an existing client without the admin's say-so.
    - Treat the code like a password, even after it was used: anyone who recorded the registration message and later learns the code can recover the client's key.
    - Pin the iteration count as a constant in your program. If client and server use different values, they derive different keys.
- **Entropy.** A fresh computer has little entropy. Before generating a long-term key, call `xEncrypt.addEntropy(tostring(os.epoch("utc")) .. event)` for every key press while the user types (for example while entering the registration code).

## Messages

- **Use the AAD.** Encrypt requests with aad `"myapp request " .. clientId` and responses with `"myapp response " .. clientId`. A request then cannot be replayed as a response or passed off as coming from another client.
- **Never run code from the network.** Do not call `textutils.unserialize`, `load` or `loadstring` on anything received, not even after `decrypt` succeeds. `textutils.unserialize` runs its input as Lua, so a registered but malicious client could loop forever or allocate gigabytes on your server. Encode messages as JSON with `textutils.serializeJSON` / `textutils.unserializeJSON` (wrapped in `pcall`), or as a fixed format you parse yourself. Then check every field's type, length and allowed values.
- **Replays.** Every request carries a random ID (`xEncrypt.toHex(xEncrypt.randomBytes(16))`) and `os.epoch("utc")`. The server rejects requests more than about 60 seconds old and IDs it has seen in the last few minutes. All computers in one world share the server's clock. The response echoes the request ID, and the client accepts only a response with its own ID.
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
- **Passwords.** Store `xEncrypt.hashPassword(password)` and check with `verifyPassword`. Require the old password to set a new one. Throttle failed logins per client, because every check costs a PBKDF2 run on the server.
- **File names.** Never use names, subjects or other request text in file paths (`../startup.lua`). Validate user names against a strict pattern such as `^[a-z0-9_-]+$`, lowercase them (servers on Windows or macOS have case-insensitive disks), and name stored files yourself, for example `os.epoch("utc") .. "-" .. xEncrypt.toHex(xEncrypt.randomBytes(4))`.
- **Disk space.** A CC computer has about 1 MB. Limit messages per user and check `fs.getFreeSpace` before writing, so one user cannot fill the disk.
- **Separate namespaces.** Prefix every settings key (`myapp.user.<name>`, `myapp.client.<id>`), so a user called `key` cannot overwrite another setting.
- **Errors.** Wrap the handling of each message in `pcall`. Log errors to a file, not to the screen.

## Known limits

- Anyone in range can jam the network by flooding it. Encryption cannot prevent that.
- A shared, public terminal can be opened by anyone who can stop the program (Ctrl+T), and its key read. Set `os.pullEvent = os.pullEventRaw` in the client so Ctrl+T does not stop it, and treat such terminals as untrusted.
- Without a key exchange such as Diffie-Hellman there is no forward secrecy: if a client key leaks, recorded traffic of that client can be decrypted.
