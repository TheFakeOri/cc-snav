--[[
  sGps.lua - Secure GPS: an authenticated, jam-resistant position-fixing
  protocol built on top of sip.lua (which itself is built on enc.lua).

  Vanilla ComputerCraft `gps.locate()` trusts whichever computers answer
  its broadcast on the "GPS" protocol - anyone in range can pretend to be
  a GPS host and feed a client a false position, and a flood of junk
  traffic on that protocol can drown out the real answers. sGps changes
  the trust model:

    - Hosts are cryptographically PINNED, not discovered on demand. A
      client only accepts a position claim from a computer ID it has
      explicitly trusted, decrypted with that host's known public key. An
      attacker without that host's private key cannot forge a valid
      response, and the sender ID itself cannot be spoofed at the
      modem/rednet layer - so "claims to be host 12" and "actually is
      computer 12" are the same thing here. sgps.trustHostById(id) fetches
      and pins a host's key automatically (trust-on-first-use, like SSH);
      sgps.trustHost(id, publicKey) pins a key you already obtained some
      other, more verified way.
    - Every request carries a fresh random nonce that the response must
      echo back inside the encrypted, integrity-checked payload. A
      captured old response (replayed later, even after a reboot resets
      sip's own sequence counters) won't match the current nonce and is
      discarded.
    - A position fix requires a QUORUM of independently authenticated
      hosts (sgps.DEFAULT_MIN_FIXES, default 4) inside a short timeout,
      with a few retries. If jamming/interference keeps that quorum from
      forming, sGps reports failure instead of guessing - it will not
      hand back a degraded or stale fix.
    - If the answering hosts disagree with each other, sGps tries each of
      them as the odd one out and keeps the exclusion that leaves the rest
      in agreement, then re-solves - so a lying or compromised host among
      a larger trusted set gets dropped rather than believed. This needs
      SPARE hosts to work: four points exactly determine a position, so a
      four-host answer fits any set of claims perfectly and cannot reveal
      a liar at all. Pin at least minFixes + 2 hosts (6 by default) if you
      want that tolerance; with fewer, an inconsistent set is reported as
      a failure instead of being resolved by guesswork.

  COST, AND THE SYMMETRIC REPLY (protocol v2): one position fix pings at
  least minFixes hosts (default 4), so anything paid per host is paid four
  times before the client knows where it is. RSA private-key operations
  are by far the most expensive thing in enc.lua - roughly five times a
  public-key one - and the original design paid one on each side per host:
  the host decrypted the request, and the CLIENT decrypted the reply.
  That last one was pure waste. The client is already sending a message
  only the host can read, so it uses that message to hand the host a
  freshly generated 16-byte symmetric key (`responseKey`), and the host
  encrypts its reply with RC4 under that key instead of under the
  client's RSA public key. Per host, per fix, that removes one RSA public
  operation on the host and the one expensive RSA private operation on
  the client. What is left is one RSA public op (client, encrypting the
  request) and one RSA private op (host, decrypting it) - and the host's
  cost is spread across however many clients it serves, while the
  client's own per-fix cost drops by roughly 4-5x.

  A fresh responseKey is generated for every single request, right
  alongside the nonce. This is not an optimisation to skip: RC4 is a
  stream cipher, and encrypting two different messages under the same key
  produces two ciphertexts whose XOR is the XOR of the plaintexts, which
  breaks both at once. One key, one message, never reused.

  PROTOCOL VERSIONS AND ROLLING UPGRADE: requests carry `v`, and hosts
  and clients may be upgraded in ANY ORDER, in any mix, with no flag day:
    - A v2 client sends `responseKey` and still sends `clientPublic`.
    - A v2 host answers with a symmetric frame when it sees a
      responseKey, and falls back to the old RSA-encrypted reply when it
      doesn't (v1 client).
    - A v1 host ignores the unknown `responseKey` field entirely and
      replies the old way. A v2 client accepts either reply shape, so it
      keeps working against un-upgraded hosts - it just still pays the
      RSA private op for those, until they're upgraded too.
  This is why `clientPublic` is still in the request even though a v2
  exchange never uses it: it is what a v1 host needs to answer at all.

  DISTANCE MEASUREMENT: a wireless modem's "modem_message" event reports
  the real, exact number of blocks a message traveled, computed by the
  game itself - no timing, guessing, or calibration needed. The catch is
  that rednet.receive() (and so sip.receive()) throws that number away
  before you ever see it. So sGps does NOT route its request/response
  traffic through sip.send/sip.receive; it talks to the modem peripheral
  directly (its own channel-per-computer-ID addressing, same idea as
  rednet), and pulls the "distance" value straight off the raw event. It
  still relies on sip/enc for identity and the actual encryption -
  sip.generateIdentity/sip.loadIdentity and enc's RSA hybrid encryption
  are used exactly as they are elsewhere, just over a transport that
  doesn't discard the one number this protocol needs.

  Requires a wireless (or ender) modem specifically - wired modems report
  a nil distance, which sGps has no use for, so sgps.open() refuses to
  bind to one instead of running blind and silently getting zero fixes.

  HONEST LIMITS - read before relying on this for anything:
    - This inherits every caveat from enc.lua/sip.lua: toy RSA, RC4, weak
      randomness, a non-cryptographic integrity checksum. Good enough to
      stop casual spoofing/eavesdropping/replay; not proven against a
      determined attacker.
    - What the echoed nonce in a symmetric reply does and does not prove:
      it proves the reply is FRESH (it matches the nonce from this
      request, so it isn't a recorded old reply) and that whoever wrote
      it knew responseKey - which only this client and the holder of the
      pinned host's RSA private key ever saw. It does NOT prove the
      ciphertext arrived unmodified: RC4 is malleable, so someone who can
      guess the plaintext can flip bits in it and flip the same bits in
      the plaintext without touching the nonce. The 8-byte keyed tag on
      the frame is what covers that case, and it is a keyed checksum, not
      a real MAC - see the comment on keyedTag. Neither proves the
      position claim is TRUE; that is what the quorum and the outlier
      rejection in solveWithOutlierRejection are for.
    - sGps opens its own modem channel (your computer ID) separate from
      rednet/sip's. It won't interfere with unrelated sip traffic, but it
      does mean sGps needs its own sgps.open(side) call even if you've
      already called sip.open() for something else.

  Usage (host, at a fixed surveyed position):
    local sgps = dofile("sGps.lua")
    sip.generateIdentity(256)  -- sip is dofile'd internally; grab it
    sgps.open("back")          -- yourself the same way if you need it too
    sgps.host(120, 64, -30)
    sgps.hostLoop()            -- blocks forever, answering requests

  Usage (client):
    local sgps = dofile("sGps.lua")
    sip.generateIdentity(256)
    sgps.open("back")
    for _, id in ipairs({12, 13, 14, 15}) do
      local key = sgps.trustHostById(id)          -- fetches + pins the key
      print(id, key and sgps.publicKeyFingerprint(key) or "unreachable")
    end                                            -- read fingerprints out
    local x, y, z, err = sgps.locate()              -- loud to double-check

  Run `sGps.lua test` to check the trilateration math and the
  request/response framing logic directly (no modem required; the raw
  modem transport itself needs real hardware/multiple computers to
  exercise and isn't covered by this self-test).
]]

local sgps = {}

local function getScriptDir()
  local ok, info = pcall(debug.getinfo, 2, "S")
  if ok and info and info.source then
    local path = info.source:match("^@(.*)$") or info.source
    local dir = path:match("^(.*)[/\\][^/\\]*$")
    if dir and dir ~= "" then return dir .. "/" end
  end
  return nil
end

local function loadSip()
  local dir = getScriptDir()
  local candidates = {}
  if dir then
    candidates[#candidates + 1] = dir .. "sip.lua"
    candidates[#candidates + 1] = dir .. "../sip.lua"
  end
  candidates[#candidates + 1] = "sip.lua"
  candidates[#candidates + 1] = "/sip.lua"
  candidates[#candidates + 1] = "/sip/sip.lua"
  for _, path in ipairs(candidates) do
    if fs.exists(path) then return dofile(path) end
  end
  error("sGps.lua: could not locate sip.lua. Place it next to sGps.lua " ..
    "(or its parent directory), or load it yourself and call sgps.useSip(sipModule).", 2)
end

local sip = loadSip()
local enc = sip.getEnc()

function sgps.useSip(mod)
  sip = mod
  enc = sip.getEnc()
end

sgps.DEFAULT_TIMEOUT = 2
sgps.DEFAULT_RETRIES = 3
sgps.DEFAULT_MIN_FIXES = 4
sgps.MAX_RESIDUAL = 2 -- blocks; distance is exact now, so honest hosts should land within noise of this

-- Wire protocol version this build speaks. v2 = symmetric replies keyed by a
-- per-request responseKey; v1 = every reply RSA-encrypted to clientPublic.
-- Both directions interoperate with v1 (see the header), so this only ever
-- needs bumping for a change that is NOT backward compatible.
sgps.PROTOCOL_VERSION = 2

-- Escape hatch for testing sGps with a wired modem, where no reply will ever
-- carry a distance and no fix can possibly succeed. Off by default so a
-- misconfigured computer complains instead of appearing connected and never
-- getting a position.
sgps.ALLOW_WIRED_MODEM = false

local state = {
  hostPosition = nil,
  trustedHosts = {}, -- [rednetId] = publicKey
  modemSide = nil
}

-- ===========================================================================
-- Raw modem transport. sip.send/sip.receive go through rednet, which reads
-- the real block-distance off the underlying "modem_message" event and
-- then throws it away before returning. sGps needs that number, so it
-- talks to the modem peripheral directly instead - same per-computer-ID
-- channel addressing rednet uses, but nothing else in common with it.
-- ===========================================================================

local function isModem(name)
  -- getType returns MULTIPLE types since CC 1.99, so a plain equality test can
  -- miss a modem that also reports another type. hasType is the right question
  -- where it exists.
  if peripheral.hasType then
    local ok, has = pcall(peripheral.hasType, name, "modem")
    if ok then return has == true end
  end
  return peripheral.getType(name) == "modem"
end

local function isWirelessModem(name)
  -- Wired modems answer isWireless() too (with false); the pcall is for the
  -- peripheral having been broken between getNames() and here.
  local ok, wireless = pcall(peripheral.call, name, "isWireless")
  return ok and wireless == true
end

-- sGps is USELESS on a wired modem, and the failure is invisible: wired
-- modem_message events carry no distance, sGps discards every reply that has
-- no distance, so the computer looks perfectly connected and simply never gets
-- a fix. The old version of this function returned the first modem of any
-- type, which on any base with wired networking is a coin flip. So: prefer
-- wireless, and report what was found so the caller can complain precisely.
-- Returns wirelessSide|nil, {wiredSides...}
local function findModems()
  local wireless, wired = nil, {}
  for _, name in ipairs(peripheral.getNames()) do
    if isModem(name) then
      if isWirelessModem(name) then
        if not wireless then wireless = name end
      else
        wired[#wired + 1] = name
      end
    end
  end
  return wireless, wired
end

local WIRED_EXPLANATION =
  "sGps needs a WIRELESS (or ender) modem: it measures how far a reply " ..
  "travelled by reading the distance field of the modem_message event, and " ..
  "wired messages have no distance, so every reply would be thrown away and " ..
  "no fix could ever succeed. Attach a wireless modem, or set " ..
  "sgps.ALLOW_WIRED_MODEM = true to bind anyway (for testing only - it will " ..
  "not locate)."

-- Opens the modem sGps talks over. Pass a side to force one, or nil to
-- autodetect (preferring wireless). Errors with a readable message rather than
-- binding to something that cannot work. Returns the side it opened.
function sgps.open(side)
  if side then
    if not peripheral.isPresent(side) then
      error("sgps.open: nothing attached on '" .. tostring(side) .. "'.", 0)
    end
    if not isModem(side) then
      error("sgps.open: the peripheral on '" .. tostring(side) .. "' is a " ..
        tostring(peripheral.getType(side)) .. ", not a modem.", 0)
    end
    if not isWirelessModem(side) and not sgps.ALLOW_WIRED_MODEM then
      error("sgps.open: the modem on '" .. tostring(side) .. "' is wired. " ..
        WIRED_EXPLANATION, 0)
    end
    state.modemSide = side
  else
    local wireless, wired = findModems()
    if wireless then
      state.modemSide = wireless
    elseif #wired > 0 and sgps.ALLOW_WIRED_MODEM then
      state.modemSide = wired[1]
    elseif #wired > 0 then
      error("sgps.open: the only modem(s) attached are wired (" ..
        table.concat(wired, ", ") .. "). " .. WIRED_EXPLANATION, 0)
    else
      error("sgps.open: no modem attached. " .. WIRED_EXPLANATION, 0)
    end
  end
  peripheral.call(state.modemSide, "open", os.getComputerID())
  return state.modemSide
end

function sgps.close()
  if state.modemSide then
    -- pcall: if the modem block is already gone, the channel went with it and
    -- there is nothing to close - that shouldn't throw out of a cleanup path.
    pcall(peripheral.call, state.modemSide, "close", os.getComputerID())
    state.modemSide = nil
  end
end

local function transmit(recipientId, message)
  assert(state.modemSide, "sgps: call sgps.open() first")
  peripheral.call(state.modemSide, "transmit", recipientId, os.getComputerID(), message)
end

-- Waits up to timeout seconds (nil = forever) for a message addressed to
-- us. Returns senderId, message, distance, or nil on timeout.
local function rawReceive(timeout)
  assert(state.modemSide, "sgps: call sgps.open() first")
  local timerId = timeout and os.startTimer(timeout)
  while true do
    local event, p1, p2, p3, p4, p5 = os.pullEvent()
    if event == "modem_message" and p1 == state.modemSide and p2 == os.getComputerID() then
      if timerId then os.cancelTimer(timerId) end
      return p3, p4, p5 -- senderId (replyChannel), message, distance
    elseif event == "timer" and p1 == timerId then
      return nil
    end
  end
end

-- ===========================================================================
-- Serialization (plain textutils, same convention as enc.lua/sip.lua)
-- ===========================================================================

local function serialize(t) return textutils.serialize(t) end

local function deserialize(s)
  local ok, v = pcall(textutils.unserialize, s)
  if ok then return v end
  return nil
end

-- 16 random bytes as 32 hex chars. Used for two different jobs of the same
-- shape: the request nonce (freshness) and the request's responseKey (the
-- symmetric key the host encrypts its reply with). Both inherit enc.lua's
-- weak randomness - math.random seeded once from the clock, not a CSPRNG.
local function random16Hex()
  local parts = {}
  for i = 1, 16 do parts[i] = string.format("%02x", math.random(0, 255)) end
  return table.concat(parts)
end

local randomNonce = random16Hex

-- Even-length hex, i.e. something that decodes to whole bytes. Used to vet
-- anything off the wire before it reaches the cipher.
local function isHexString(s, exactLen)
  if type(s) ~= "string" then return false end
  if exactLen and #s ~= exactLen then return false end
  return #s % 2 == 0 and s:match("^%x*$") ~= nil
end

-- Key components are bignums printed with no leading zero, so their hex is
-- often an odd number of characters (the public exponent 65537 is "10001").
-- Nothing decodes them to bytes, so only hex-ness matters.
local function looksLikeKeyComponent(s)
  return type(s) == "string" and s:match("^%x+$") ~= nil
end

-- ===========================================================================
-- Symmetric response frame (protocol v2)
--
-- The host encrypts LOCATE_RESPONSE with RC4 under the responseKey the client
-- sent inside its RSA-encrypted request, instead of RSA-encrypting it to the
-- client's public key. That is the whole optimisation: it deletes the client's
-- per-host RSA private-key operation, which was the single most expensive step
-- in a fix.
--
-- Frame shape is deliberately distinguishable from enc.encrypt's RSA package:
--   symmetric : {sv = 2, data = <hex>, tag = <hex 16>}
--   RSA (v1)  : {key = <hex>, data = <hex>}
-- so a client can tell which kind of reply it got by looking, and never tries
-- to RSA-decrypt a symmetric frame or vice versa.
-- ===========================================================================

local SYM_FRAME_VERSION = 2

-- enc.lua owns the RC4 implementation; borrowing it keeps one cipher in the
-- project rather than a second copy that could drift. These live in
-- enc._internal, which enc.lua labels as not-a-stable-API, so this is resolved
-- per call (enc can be swapped by sgps.useSip) and complains clearly if a
-- future enc.lua moves them.
local function symPrims()
  local p = enc._internal
  if not (p and p.rc4Init and p.rc4Crypt and p.bytesToHex and p.hexToBytes) then
    error("sGps: this enc.lua does not expose the RC4 primitives sGps needs " ..
      "for protocol v2 symmetric replies (enc._internal.rc4Init, rc4Crypt, " ..
      "bytesToHex, hexToBytes). Update enc.lua alongside sGps.lua.", 0)
  end
  return p
end

local function strToBytes(s)
  local bytes = {}
  for i = 1, #s do bytes[i] = s:byte(i) end
  return bytes
end

local function bytesToStr(bytes)
  local n = #bytes
  if n <= 200 then return string.char(table.unpack(bytes, 1, n)) end
  -- string.char has an argument-count limit, so chunk longer payloads.
  local chunks = {}
  for i = 1, n, 200 do
    chunks[#chunks + 1] = string.char(table.unpack(bytes, i, math.min(i + 199, n)))
  end
  return table.concat(chunks)
end

-- (a * b) mod 2^32 without losing precision. Lua numbers here are doubles, so
-- a bare 32x32 multiply silently overflows 2^53 and rounds; splitting the left
-- operand keeps every partial product exact. (No bit operators: CC's Lua 5.2
-- has no &, |, <<, >> - bit32 and arithmetic only.)
local function mul32(a, b)
  local ah = math.floor(a / 65536)
  return ((ah * b) % 65536 * 65536 + (a % 65536) * b) % 4294967296
end

-- 8-byte keyed tag over the ciphertext, keyed by a subkey of responseKey.
--
-- HONESTLY: this is NOT a cryptographic MAC. It is two FNV-style accumulators
-- over tagKey .. ciphertext, and nothing about it is proven. What it buys is
-- that the raw stream cipher underneath is no longer trivially malleable: an
-- attacker who can guess the plaintext of a reply (host coordinates are not
-- secret) could otherwise XOR a delta into the ciphertext's x/y/z bytes,
-- leaving the nonce check happy while moving the reported position. To do that
-- through this tag they would have to produce a matching tag without knowing
-- tagKey, and the accumulator is non-linear over XOR so the tag of a modified
-- message cannot be derived from the tag of the original. Guessing is 2^-64.
-- A real MAC needs a hash function, which this project does not have.
local function keyedTag(tagKey, dataBytes)
  local bxor = bit32.bxor
  local h1, h2 = 2166136261, 2654435769
  for i = 1, #tagKey do
    h1 = mul32(bxor(h1, tagKey[i]), 16777619)
    h2 = mul32(bxor(h2, tagKey[i]), 2246822519)
  end
  for i = 1, #dataBytes do
    local b = dataBytes[i]
    h1 = mul32(bxor(h1, b), 16777619)
    -- Mixing the index in as well so that reordering bytes changes the tag.
    h2 = mul32(bxor(h2 + i, b), 2246822519)
  end
  return string.format("%08x%08x", h1, h2)
end

-- Splits the one 16-byte responseKey into a cipher key and a tag key by
-- running RC4 keyed with it over zeros and slicing the keystream. The first 16
-- output bytes are dropped because RC4's early keystream is its most biased
-- part. This is RC4-as-a-PRF rather than a real KDF; its only job is to keep
-- the tag key from being the same bytes as the cipher key, so that a plaintext
-- guess (which reveals cipher keystream) reveals nothing about the tag key.
local function deriveSubkeys(keyHex)
  local p = symPrims()
  local zeros = {}
  for i = 1, 48 do zeros[i] = 0 end
  local ks = p.rc4Crypt(p.rc4Init(p.hexToBytes(keyHex)), zeros)
  local cipherKey, tagKey = {}, {}
  for i = 1, 16 do
    cipherKey[i] = ks[16 + i]
    tagKey[i] = ks[32 + i]
  end
  return cipherKey, tagKey
end

local function symEncrypt(keyHex, message)
  assert(isHexString(keyHex, 32), "sgps: symmetric key must be 32 hex chars")
  local p = symPrims()
  local cipherKey, tagKey = deriveSubkeys(keyHex)
  local cipher = p.rc4Crypt(p.rc4Init(cipherKey), strToBytes(message))
  return {
    sv = SYM_FRAME_VERSION,
    data = p.bytesToHex(cipher),
    tag = keyedTag(tagKey, cipher)
  }
end

-- Returns plaintext, nil or nil, err. Never throws on a hostile frame: every
-- field is checked before it reaches the cipher.
local function symDecrypt(keyHex, package)
  if type(package) ~= "table" or package.sv ~= SYM_FRAME_VERSION then
    return nil, "not_symmetric_frame"
  end
  if not isHexString(package.data) or not isHexString(package.tag, 16) then
    return nil, "malformed_frame"
  end
  if not isHexString(keyHex, 32) then return nil, "no_response_key" end
  local p = symPrims()
  local cipherKey, tagKey = deriveSubkeys(keyHex)
  local cipher = p.hexToBytes(package.data)
  if keyedTag(tagKey, cipher) ~= package.tag then return nil, "bad_tag" end
  return bytesToStr(p.rc4Crypt(p.rc4Init(cipherKey), cipher)), nil
end

-- ===========================================================================
-- Trusted host directory
-- ===========================================================================

-- Validated at the point of pinning, not at the point of use: a key with a
-- non-hex n or e makes enc.encrypt throw, and that throw would otherwise
-- surface much later inside locate()'s parallel fan-out, where it reads as a
-- mysterious failure of the whole fix rather than as "that key is junk".
function sgps.trustHost(id, publicKey)
  if type(id) ~= "number" then
    error("sgps.trustHost: id must be a computer ID (number), got " .. type(id), 2)
  end
  if not (type(publicKey) == "table" and looksLikeKeyComponent(publicKey.n) and
          looksLikeKeyComponent(publicKey.e)) then
    error("sgps.trustHost: publicKey must be a table with hex-string n and e " ..
      "fields, as produced by enc.generateKeyPair", 2)
  end
  state.trustedHosts[id] = publicKey
end

function sgps.listTrustedHosts()
  local ids = {}
  for id in pairs(state.trustedHosts) do ids[#ids + 1] = id end
  return ids
end

-- A short, human-comparable code derived from a public key - not
-- cryptographically unforgeable, just enough to read out loud/type into
-- chat so two people can confirm they both see the same key, the same way
-- SSH host key fingerprints work.
function sgps.publicKeyFingerprint(publicKey)
  local s = (publicKey.n or "") .. ":" .. (publicKey.e or "")
  local h1, h2 = 0, 0
  for i = 1, #s do
    local b = s:byte(i)
    h1 = (h1 * 33 + b) % 65536
    h2 = (h2 * 131 + b + i) % 65536
  end
  return string.format("%04X-%04X", h1, h2)
end

local function buildIdentifyRequest()
  return serialize({type = "IDENTIFY_REQUEST"})
end

local function handleIdentifyRequestOnHost(payload, myPublicKey)
  local request = deserialize(payload)
  if not (type(request) == "table" and request.type == "IDENTIFY_REQUEST") then
    return nil, "malformed_request"
  end
  return serialize({type = "IDENTIFY_RESPONSE", publicKey = myPublicKey}), nil
end

-- Validates the shape of a public key as well as the envelope. A key whose n/e
-- aren't hex strings is not merely useless: enc.encrypt THROWS on it, so
-- pinning one used to plant an error that only surfaced later, inside a
-- parallel fan-out in locate(), taking the whole fix down.
local function parseIdentifyResponse(payload)
  local response = deserialize(payload)
  if not (type(response) == "table" and response.type == "IDENTIFY_RESPONSE" and
          type(response.publicKey) == "table") then
    return nil, "malformed_response"
  end
  local key = response.publicKey
  if not (looksLikeKeyComponent(key.n) and looksLikeKeyComponent(key.e)) then
    return nil, "malformed_public_key"
  end
  return key, nil
end

-- Trust-on-first-use: asks computer `id` directly for its public key over
-- the open air and pins whatever comes back - no pre-shared key file
-- needed. This is safe against anyone who ISN'T that specific computer,
-- since rednet/modem sender IDs can't be spoofed - but exactly like SSH's
-- "the authenticity of this host can't be established" warning on a first
-- connection, it can't prove computer `id` is actually the host you think
-- it is (wrong ID, typo, or a host that was never really yours). Do this
-- at a moment you're confident about that, and ideally cross-check
-- sgps.publicKeyFingerprint(key) against the host out-of-band (voice,
-- chat, a sign next to it) for real assurance. For anything you actually
-- care about getting right, sgps.trustHost(id, publicKey) with a key you
-- obtained some other verified way remains the stronger option.
-- Returns the pinned public key, or nil, err.
function sgps.trustHostById(id, timeout)
  transmit(id, buildIdentifyRequest())
  local deadline = os.clock() + (timeout or sgps.DEFAULT_TIMEOUT)
  while true do
    local remaining = deadline - os.clock()
    if remaining <= 0 then return nil, "timeout" end
    local senderId, payload = rawReceive(remaining)
    if senderId == id and type(payload) == "string" then
      local publicKey, err = parseIdentifyResponse(payload)
      if publicKey then
        sgps.trustHost(id, publicKey)
        return publicKey, nil
      end
    end
  end
end

function sgps.saveTrustedHosts(path)
  local f, err = fs.open(path, "w")
  if not f then
    error("sgps.saveTrustedHosts: could not open " .. tostring(path) .. ": " ..
      tostring(err), 0)
  end
  f.write(serialize(state.trustedHosts))
  f.close()
end

-- Returns true, count on success or nil, err. A truncated or corrupt file used
-- to silently install an EMPTY trust store, which reads downstream as "no hosts
-- are pinned" - indistinguishable from a fresh install, and it discards the
-- pinned keys already in memory. Say so instead, and leave the in-memory store
-- alone.
function sgps.loadTrustedHosts(path)
  local f, err = fs.open(path, "r")
  if not f then
    return nil, "could not open " .. tostring(path) .. ": " .. tostring(err)
  end
  local raw = f.readAll()
  f.close()
  local data = deserialize(raw)
  if type(data) ~= "table" then
    return nil, "trusted host file " .. tostring(path) .. " is corrupt or empty"
  end
  state.trustedHosts = data
  local n = 0
  for _ in pairs(data) do n = n + 1 end
  return true, n
end

-- ===========================================================================
-- Pure trilateration math (no networking) - given >=4 {x=,y=,z=,d=} points,
-- solve for the unknown position via linearized least squares.
-- ===========================================================================

-- Gaussian elimination with partial pivoting for a 3x3 system M*x = v.
local function solveLinear3(M, v)
  local A = {
    {M[1][1], M[1][2], M[1][3], v[1]},
    {M[2][1], M[2][2], M[2][3], v[2]},
    {M[3][1], M[3][2], M[3][3], v[3]}
  }
  for col = 1, 3 do
    local pivotRow, pivotVal = col, math.abs(A[col][col])
    for row = col + 1, 3 do
      if math.abs(A[row][col]) > pivotVal then
        pivotRow, pivotVal = row, math.abs(A[row][col])
      end
    end
    if pivotVal < 1e-9 then return nil, "singular" end
    A[col], A[pivotRow] = A[pivotRow], A[col]
    for row = col + 1, 3 do
      local factor = A[row][col] / A[col][col]
      for c = col, 4 do A[row][c] = A[row][c] - factor * A[col][c] end
    end
  end
  local x = {0, 0, 0}
  for row = 3, 1, -1 do
    local sum = A[row][4]
    for c = row + 1, 3 do sum = sum - A[row][c] * x[c] end
    x[row] = sum / A[row][row]
  end
  return x, nil
end

-- Returns x, y, z, nil on success, or nil, nil, nil, err on failure.
local function trilaterate(points)
  if #points < 4 then return nil, nil, nil, "insufficient_points" end
  local ref = points[1]
  local A, b = {}, {}
  for i = 2, #points do
    local p = points[i]
    A[#A + 1] = {2 * (p.x - ref.x), 2 * (p.y - ref.y), 2 * (p.z - ref.z)}
    b[#b + 1] = (p.x ^ 2 - ref.x ^ 2) + (p.y ^ 2 - ref.y ^ 2) + (p.z ^ 2 - ref.z ^ 2) -
      (p.d ^ 2 - ref.d ^ 2)
  end

  local ATA = {{0, 0, 0}, {0, 0, 0}, {0, 0, 0}}
  local ATb = {0, 0, 0}
  for i = 1, #A do
    for r = 1, 3 do
      for c = 1, 3 do ATA[r][c] = ATA[r][c] + A[i][r] * A[i][c] end
      ATb[r] = ATb[r] + A[i][r] * b[i]
    end
  end

  local solution, err = solveLinear3(ATA, ATb)
  if not solution then return nil, nil, nil, err end
  return solution[1], solution[2], solution[3], nil
end

-- How far the worst of these points is from agreeing with a candidate
-- position: 0 means every claimed distance matches exactly.
local function worstResidual(pts, x, y, z)
  local worst = 0
  for _, p in ipairs(pts) do
    local predicted = math.sqrt((x - p.x) ^ 2 + (y - p.y) ^ 2 + (z - p.z) ^ 2)
    worst = math.max(worst, math.abs(predicted - p.d))
  end
  return worst
end

-- Solves for position, dropping hosts whose claims don't fit, as long as
-- enough points remain to check the survivors against each other. Returns
-- x, y, z, nil or nil, nil, nil, err ("inconsistent_hosts",
-- "too_many_outliers", "insufficient_points", "singular").
--
-- The redundancy budget is the whole story here. Three unknowns need three
-- equations, and trilaterate builds one per point after the first, so
-- minFixes = 4 points is EXACTLY determined: it fits any set of claims
-- perfectly, liar included, and produces a residual of zero either way. No
-- amount of residual arithmetic can find a liar in a set that small - the
-- data simply doesn't contain the answer.
--
-- So when the full set disagrees with itself, each host is tried as the one
-- left OUT, and the exclusion kept is the one whose REMAINING hosts agree with
-- each other. That test only means something while the remaining subset still
-- has a redundant measurement in it, which is why this refuses (rather than
-- guesses) as soon as dropping one would leave exactly minFixes points.
--
-- The previous version scored candidates by the LEFT-OUT host's own residual,
-- on the theory that leaving an honest host out drags the solution further than
-- leaving the liar out. That is not sound, and it wasn't just a theoretical
-- gap: on a plausible 5-host layout (four honest hosts plus one claiming a
-- position 60 blocks from where it really was) it consistently preferred to
-- drop an honest host, kept the liar, and returned a position ~99 blocks wrong
-- with err = nil - a confident, silent lie, which is the one thing a
-- jam-resistant GPS must never do. Tolerating a bad host now genuinely
-- requires minFixes + 2 pinned hosts (6 by default); with minFixes + 1 it
-- reports "inconsistent_hosts" and the operator has to find out which host is
-- wrong, e.g. with sgps.diagnose().
function sgps.solveWithOutlierRejection(points, minFixes)
  minFixes = minFixes or sgps.DEFAULT_MIN_FIXES
  local pts = {}
  for i, p in ipairs(points) do pts[i] = p end

  while true do
    if #pts < minFixes then return nil, nil, nil, "too_many_outliers" end

    local x, y, z, err = trilaterate(pts)
    if not x then return nil, nil, nil, err end

    if worstResidual(pts, x, y, z) <= sgps.MAX_RESIDUAL then
      return x, y, z, nil
    end

    -- Dropping one would leave an exactly-determined set, which fits anything.
    if #pts - 1 < minFixes + 1 then
      return nil, nil, nil, "inconsistent_hosts"
    end

    local bestDrop, bestScore, bestExcluded = nil, math.huge, -math.huge
    for dropIdx = 1, #pts do
      local subset = {}
      for i, p in ipairs(pts) do
        if i ~= dropIdx then subset[#subset + 1] = p end
      end
      local sx, sy, sz = trilaterate(subset)
      if sx then
        -- Primary score: do the hosts that are LEFT agree with each other?
        local score = worstResidual(subset, sx, sy, sz)
        local dropped = pts[dropIdx]
        local predicted = math.sqrt((sx - dropped.x) ^ 2 + (sy - dropped.y) ^ 2 +
          (sz - dropped.z) ^ 2)
        local excluded = math.abs(predicted - dropped.d)
        -- Tie-break: among subsets that fit equally well, drop the host that
        -- disagrees with its subset the most.
        if score < bestScore - 1e-9 or
           (math.abs(score - bestScore) <= 1e-9 and excluded > bestExcluded) then
          bestDrop, bestScore, bestExcluded = dropIdx, score, excluded
        end
      end
    end

    -- No single exclusion makes the rest agree: more than one host is wrong, or
    -- the geometry is degenerate. Either way, don't invent a position.
    if not bestDrop or bestScore > sgps.MAX_RESIDUAL then
      return nil, nil, nil, "too_many_outliers"
    end
    table.remove(pts, bestDrop)
  end
end

-- ===========================================================================
-- Request/response framing (pure, testable independent of rednet)
-- ===========================================================================

-- Returns the serialized request, the nonce, and the responseKey. Both random
-- values are fresh for every single request - see the header on why reusing a
-- responseKey across two replies would be catastrophic.
local function buildRequest(myPublicKey)
  local nonce = randomNonce()
  local responseKey = random16Hex()
  local request = serialize({
    type = "LOCATE_REQUEST",
    v = sgps.PROTOCOL_VERSION,
    nonce = nonce,
    responseKey = responseKey,
    -- Still sent, and still required by a v1 host, which has no idea what
    -- responseKey is and can only answer by RSA-encrypting to this key.
    clientPublic = myPublicKey
  })
  return request, nonce, responseKey
end

-- Given a decrypted request string and this host's fixed position, returns the
-- serialized response plus a `meta` table describing how to seal it
-- (meta.responseKey for v2, meta.clientPublic for the v1 fallback), or
-- nil, nil, err. Pure: no keys, no modem, no RSA - sealResponse does that.
local function handleRequestOnHost(message, hostPosition)
  local request = deserialize(message)
  if not (type(request) == "table" and request.type == "LOCATE_REQUEST" and
          type(request.nonce) == "string") then
    return nil, nil, "malformed_request"
  end

  -- A responseKey that isn't a 32-hex-char string is either a v1 client (nil,
  -- fine) or junk (rejected here, so it can never reach the cipher).
  local responseKey = nil
  if request.responseKey ~= nil then
    if not isHexString(request.responseKey, 32) then
      return nil, nil, "malformed_request"
    end
    responseKey = request.responseKey
  end

  -- Vetted, not just present: enc.encrypt throws on a key whose n/e aren't
  -- hex, and on the legacy path that call happens on the HOST, where a throw
  -- would take the host loop down (it's pcall'd there now, but not answering a
  -- request at all beats answering it by dying).
  local clientPublic = request.clientPublic
  local clientPublicUsable = type(clientPublic) == "table" and
    looksLikeKeyComponent(clientPublic.n) and looksLikeKeyComponent(clientPublic.e)

  -- Without a responseKey the only way to answer is the RSA fallback, so a
  -- request with neither is unanswerable rather than merely old.
  if not responseKey and not clientPublicUsable then
    return nil, nil, "malformed_request"
  end

  local response = serialize({
    type = "LOCATE_RESPONSE",
    v = responseKey and sgps.PROTOCOL_VERSION or 1,
    nonce = request.nonce,
    x = hostPosition.x,
    y = hostPosition.y,
    z = hostPosition.z
  })
  return response, {
    responseKey = responseKey,
    clientPublic = clientPublicUsable and clientPublic or nil,
    clientVersion = tonumber(request.v) or 1
  }, nil
end

-- Wraps a plaintext response for the wire. Returns package, mode.
-- v2 (responseKey present): RC4 under that key - no RSA on this side at all.
-- v1 (no responseKey): the original RSA-encrypt-to-clientPublic path, kept so
-- an upgraded host keeps answering un-upgraded clients.
local function sealResponse(response, meta)
  if meta.responseKey then
    return symEncrypt(meta.responseKey, response), "symmetric"
  end
  return enc.encrypt(meta.clientPublic, response), "rsa"
end

-- Client-side counterpart: accepts either reply shape, so an upgraded client
-- keeps working against un-upgraded hosts. Returns plaintext, nil, mode or
-- nil, err. `myPrivateKey` is only touched on the legacy path, which is the
-- point - the RSA private operation is what this whole change avoids.
local function openResponse(package, responseKey, myPrivateKey)
  if type(package) ~= "table" then return nil, "malformed_package" end
  if package.sv ~= nil then
    local message, err = symDecrypt(responseKey, package)
    if not message then return nil, err end
    return message, nil, "symmetric"
  end
  if package.key and package.data then
    local ok, message = pcall(enc.decrypt, myPrivateKey, package)
    if not ok or type(message) ~= "string" then return nil, "rsa_decrypt_failed" end
    return message, nil, "rsa"
  end
  return nil, "malformed_package"
end

-- Given a decrypted response string and the nonce we expect it to echo,
-- returns the response table, or nil, err.
--
-- The nonce check is the freshness guarantee for BOTH reply shapes: a recorded
-- old reply (even one recorded before a reboot reset sip's sequence counters)
-- echoes a nonce that is no longer current and is discarded here. On the
-- symmetric path it also means the writer knew responseKey, which only this
-- client and the pinned host's RSA private key ever saw. It is not an
-- integrity check on the ciphertext - see keyedTag - and it says nothing about
-- whether the coordinates are true.
local function parseResponse(message, expectedNonce)
  local response = deserialize(message)
  if not (type(response) == "table" and response.type == "LOCATE_RESPONSE" and
          response.nonce == expectedNonce) then
    return nil, "invalid_or_stale_response"
  end
  return response, nil
end

sgps._internal = {
  trilaterate = trilaterate,
  buildRequest = buildRequest,
  handleRequestOnHost = handleRequestOnHost,
  sealResponse = sealResponse,
  openResponse = openResponse,
  parseResponse = parseResponse,
  symEncrypt = symEncrypt,
  symDecrypt = symDecrypt,
  buildIdentifyRequest = buildIdentifyRequest,
  handleIdentifyRequestOnHost = handleIdentifyRequestOnHost,
  parseIdentifyResponse = parseIdentifyResponse,
  findModems = findModems
}

-- ===========================================================================
-- Host side
-- ===========================================================================

function sgps.host(x, y, z)
  state.hostPosition = {x = x, y = y, z = z}
end

-- Blocks forever, answering IDENTIFY_REQUESTs (so clients can
-- sgps.trustHostById this computer) and LOCATE_REQUESTs. Run via
-- parallel.waitForAny alongside anything else the host needs to do.
function sgps.hostLoop()
  assert(state.hostPosition, "sgps.host(x, y, z) must be called before sgps.hostLoop()")
  local myPrivateKey = sip.getPrivateKey()
  local myPublicKey = sip.getPublicKey()

  -- Answering one request must never be able to kill the loop. Everything below
  -- runs on bytes an unknown computer chose, and it used to be only partly
  -- guarded: enc.decrypt was pcall'd but enc.encrypt was not, so a client that
  -- sent a junk clientPublic (a modulus too small for enc's 16-byte session
  -- key, say) made enc.encrypt throw, the host process died, and from then on
  -- every legitimate client timed out forever with no diagnostic anywhere.
  -- transmit can throw too, if the modem block was broken mid-reply.
  local function answer(senderId, payload)
    if type(payload) == "string" then
      local reply = handleIdentifyRequestOnHost(payload, myPublicKey)
      if reply then transmit(senderId, reply) end
    elseif type(payload) == "table" then
      local message = enc.decrypt(myPrivateKey, payload)
      local response, meta = handleRequestOnHost(message, state.hostPosition)
      if response then
        transmit(senderId, sealResponse(response, meta))
      end
    end
  end

  while true do
    local senderId, payload = rawReceive()
    if senderId then
      local ok, err = pcall(answer, senderId, payload)
      -- Ctrl+T reaches us as an error through os.pullEvent; swallowing it would
      -- make the host unkillable.
      if not ok and err == "Terminated" then error(err, 0) end
    end
  end
end

-- ===========================================================================
-- Client side
-- ===========================================================================

-- Sends one request to hostId and blocks up to timeout seconds for a
-- matching, freshly-nonced reply. Returns the measured {x,y,z,d}, or nil, err.
local function pingHost(hostId, hostPublicKey, timeout)
  local payload, nonce, responseKey = buildRequest(sip.getPublicKey())
  -- The one RSA operation left on the client per host: a public-key encrypt,
  -- which is ~5x cheaper than the private-key decrypt this used to also pay
  -- when the reply came back.
  transmit(hostId, enc.encrypt(hostPublicKey, payload))
  local myPrivateKey = sip.getPrivateKey()

  local deadline = os.clock() + timeout
  while true do
    local remaining = deadline - os.clock()
    if remaining <= 0 then return nil, "timeout" end
    local senderId, package, distance = rawReceive(remaining)
    if senderId == hostId and type(package) == "table" and type(distance) == "number" then
      -- Either shape: a v2 symmetric frame (no RSA at all here) or a v1
      -- RSA package from a host that hasn't been upgraded yet.
      local message, _, mode = openResponse(package, responseKey, myPrivateKey)
      if message then
        local response = parseResponse(message, nonce)
        if response then
          return {
            x = response.x, y = response.y, z = response.z,
            d = distance, hostId = senderId, mode = mode
          }
        end
        -- wrong/stale nonce from this host: keep waiting for the real reply
      end
    end
  end
end

-- Returns x, y, z, nil on a successful fix, or nil, nil, nil, err (e.g.
-- "insufficient_fixes" if jamming/interference prevented quorum).
function sgps.locate(opts)
  -- Preflight, because the per-host errors below are deliberately swallowed:
  -- without this, forgetting sgps.open() looks exactly like every host being
  -- out of range.
  assert(state.modemSide, "sgps.locate: call sgps.open() first")
  opts = opts or {}
  local timeout = opts.timeout or sgps.DEFAULT_TIMEOUT
  local retries = opts.retries or sgps.DEFAULT_RETRIES
  local minFixes = opts.minFixes or sgps.DEFAULT_MIN_FIXES

  local hostIds = opts.hostIds
  if not hostIds then
    hostIds = sgps.listTrustedHosts()
  end
  assert(#hostIds >= minFixes,
    "sgps.locate: fewer trusted hosts (" .. #hostIds .. ") than minFixes (" .. minFixes .. ")")

  -- Answers accumulate across retries, keyed by host. Resetting them each
  -- attempt (as this used to) meant a link where different hosts drop out on
  -- different attempts never reached quorum, even with every host reachable:
  -- three answers now plus three answers a moment later still counted as
  -- three. Hosts that already answered aren't re-pinged, so retries get
  -- cheaper as the set fills up.
  --
  -- The cost is that a point can be up to a couple of retries old, so on a
  -- fast-moving ship the distances blend slightly different moments. Pass
  -- opts.accumulate = false to demand all answers within one attempt instead.
  local accumulate = opts.accumulate ~= false
  local answers = {}
  -- Counted as answers land rather than walked with pairs() on every check:
  -- this is read once per attempt and once more to build the failure message,
  -- and the table is keyed by host ID so # doesn't work on it.
  local answerCount = 0
  local lastSolveError = nil

  for attempt = 1, retries do
    if not accumulate then answers, answerCount = {}, 0 end

    local pending = {}
    for _, id in ipairs(hostIds) do
      if not answers[id] then pending[#pending + 1] = id end
    end

    if #pending > 0 then
      local thunks = {}
      for _, id in ipairs(pending) do
        thunks[#thunks + 1] = function()
          local hostPublicKey = state.trustedHosts[id]
          if hostPublicKey then
            -- One bad host must not take down the whole fix. An error in any
            -- waitForAll coroutine aborts the entire call, so an unusable
            -- pinned key (enc.encrypt refuses a modulus that's too small) or a
            -- modem broken mid-fix used to turn a recoverable "that host
            -- didn't answer" into locate() throwing at the caller.
            local ok, point = pcall(pingHost, id, hostPublicKey, timeout)
            if not ok then
              -- Ctrl+T arrives as an error through os.pullEvent inside
              -- pingHost; re-raise so the fix stays interruptible.
              if point == "Terminated" then error(point, 0) end
            elseif point and not answers[id] then
              answers[id] = point
              answerCount = answerCount + 1
            end
          end
        end
      end
      parallel.waitForAll(table.unpack(thunks))
    end

    if answerCount >= minFixes then
      local points = {}
      for _, point in pairs(answers) do points[#points + 1] = point end
      local x, y, z, err = sgps.solveWithOutlierRejection(points, minFixes)
      if x then return x, y, z, nil end
      -- Quorum was reached and the solve still failed, which is a different
      -- problem from nobody answering ("inconsistent_hosts" = someone is
      -- lying or mis-surveyed; "singular" = the hosts are coplanar). Keep it
      -- for the error message instead of reporting a misleading shortfall.
      lastSolveError = err
    end

    -- sleep() is a filtered pull, so a straggler reply that lands during this
    -- backoff is discarded. That's accepted rather than fixed: the host it came
    -- from is simply re-pinged on the next attempt (one cheap public-key op),
    -- and draining the queue here would mean re-implementing the whole
    -- receive/verify path outside the per-host coroutines that own the nonces.
    if attempt < retries then sleep(0.5 * attempt) end
  end

  -- Say how close it got: "2 of 5 answered" points at radio range or dead
  -- hosts, while enough answers plus a solver complaint points at the hosts
  -- themselves - bad geometry, a wrong surveyed position, or a liar.
  if lastSolveError then
    return nil, nil, nil, string.format(
      "no_fix: %s (%d of %d hosts answered, need %d)",
      lastSolveError, answerCount, #hostIds, minFixes)
  end
  return nil, nil, nil, string.format("insufficient_fixes (%d of %d hosts answered, need %d)",
    answerCount, #hostIds, minFixes)
end

-- ===========================================================================
-- Diagnostics
-- ===========================================================================

-- What radio are we actually using? A wired modem reports nil distance on every
-- message, and sGps discards replies without a distance - so a computer that
-- picked up a wired modem gets zero fixes while looking perfectly connected.
function sgps.modemInfo()
  if not state.modemSide then return nil end
  local ok, wireless = pcall(peripheral.call, state.modemSide, "isWireless")
  return {
    side = state.modemSide,
    wireless = (ok and wireless) and true or false,
    known = ok
  }
end

-- Plaintext reachability test: the IDENTIFY exchange, which involves no
-- encryption and no pinned key. Separating this from a full position ping is
-- the whole point - if probe succeeds but the ping doesn't, the radio is fine
-- and the problem is the keys; if probe itself fails, nothing else matters.
-- Returns a table: {ok, distance, distanceMissing, key, latency, err}
function sgps.probe(hostId, timeout)
  timeout = timeout or sgps.DEFAULT_TIMEOUT
  local started = os.clock()
  transmit(hostId, buildIdentifyRequest())

  local deadline = started + timeout
  while true do
    local remaining = deadline - os.clock()
    if remaining <= 0 then
      return {ok = false, err = "no reply", latency = os.clock() - started}
    end
    local senderId, payload, distance = rawReceive(remaining)
    if senderId == hostId and type(payload) == "string" then
      local key = parseIdentifyResponse(payload)
      if key then
        return {
          ok = true,
          key = key,
          distance = type(distance) == "number" and distance or nil,
          distanceMissing = type(distance) ~= "number",
          latency = os.clock() - started
        }
      end
    end
  end
end

-- Tests every host two ways: a plaintext probe (is it there at all?) and a full
-- encrypted position ping (do the keys work?). Reporting both separates causes
-- that look identical from the outside. Returns a list, sorted by host ID, of
--   {hostId, reachable, probeDistance, distanceMissing, keyPinned, keyChanged,
--    ok, distance, latency, x, y, z, err}
function sgps.diagnose(opts)
  assert(state.modemSide, "sgps.diagnose: call sgps.open() first")
  opts = opts or {}
  local timeout = opts.timeout or sgps.DEFAULT_TIMEOUT
  local hostIds = opts.hostIds or sgps.listTrustedHosts()

  local results = {}
  local thunks = {}
  for _, id in ipairs(hostIds) do
    thunks[#thunks + 1] = function()
      local entry = {hostId = id}

      -- Same reasoning as in locate(): an error in any waitForAll coroutine
      -- aborts the whole call, and a diagnostic tool that dies on the one host
      -- that has a problem is exactly backwards.
      local probeOk, probe = pcall(sgps.probe, id, timeout)
      if not probeOk then
        if probe == "Terminated" then error(probe, 0) end
        probe = {ok = false, err = "error: " .. tostring(probe)}
      end
      entry.reachable = probe.ok
      entry.probeDistance = probe.distance
      entry.distanceMissing = probe.ok and probe.distanceMissing or false

      local pinned = state.trustedHosts[id]
      entry.keyPinned = pinned ~= nil

      -- A host that regenerated its keypair still answers a probe, but nothing
      -- it says can be decrypted with the key we pinned. Catch that explicitly
      -- rather than reporting it as a mysterious timeout.
      if probe.ok and pinned and probe.key then
        entry.keyChanged = (probe.key.n ~= pinned.n) or (probe.key.e ~= pinned.e)
      end

      if not probe.ok then
        entry.ok = false
        entry.err = probe.err or "unreachable"
      elseif not pinned then
        entry.ok = false
        entry.err = "no pinned key"
      else
        local started = os.clock()
        local pingOk, point, err = pcall(pingHost, id, pinned, timeout)
        entry.latency = os.clock() - started
        if not pingOk then
          if point == "Terminated" then error(point, 0) end
          entry.ok = false
          entry.err = "error: " .. tostring(point)
        elseif point then
          entry.ok = true
          entry.distance, entry.x, entry.y, entry.z = point.d, point.x, point.y, point.z
          -- Which reply shape the host used: "symmetric" = upgraded to v2,
          -- "rsa" = still on v1 and still costing this client an RSA private
          -- op per fix. Handy for confirming a rolling upgrade actually landed.
          entry.replyMode = point.mode
        else
          entry.ok = false
          entry.err = err or "no reply to position request"
        end
      end

      results[#results + 1] = entry
    end
  end

  if #thunks > 0 then parallel.waitForAll(table.unpack(thunks)) end
  table.sort(results, function(a, b) return a.hostId < b.hostId end)
  return results
end

-- Checks whether the hosts that answered are too flat to solve from. Four
-- hosts at the same altitude pin down X and Z but leave Y almost free, so the
-- solver either fails or returns a confident, wrong height. Returns ok, reason.
function sgps.checkGeometry(results)
  local ys, xs, zs = {}, {}, {}
  for _, r in ipairs(results) do
    if r.ok then
      ys[#ys + 1] = r.y
      xs[#xs + 1] = r.x
      zs[#zs + 1] = r.z
    end
  end
  if #ys < 4 then return false, "fewer than 4 hosts answered" end

  local function spread(values)
    local lo, hi = values[1], values[1]
    for _, v in ipairs(values) do
      if v < lo then lo = v end
      if v > hi then hi = v end
    end
    return hi - lo
  end

  local ySpread = spread(ys)
  local horizontalSpread = math.max(spread(xs), spread(zs))
  if ySpread < 1 then
    return false, string.format(
      "all answering hosts are at the same altitude (Y spread %.1f) - altitude " ..
      "cannot be solved; move one host well above or below the others", ySpread)
  end
  if horizontalSpread > 0 and ySpread < horizontalSpread * 0.1 then
    return false, string.format(
      "hosts are nearly coplanar (Y spread %.1f vs %.1f horizontal) - altitude " ..
      "will be imprecise; raise or lower one host", ySpread, horizontalSpread)
  end
  return true, string.format("Y spread %.1f, horizontal spread %.1f",
    ySpread, horizontalSpread)
end

-- ===========================================================================
-- Self-test: trilateration math + request/response framing, no modem needed.
-- ===========================================================================

function sgps.selfTest()
  local allPassed = true
  local function check(name, ok)
    ok = not not ok
    print((ok and "PASS " or "FAIL ") .. name)
    allPassed = allPassed and ok
  end

  local truth = {x = 100, y = 64, z = -50}
  local hostPositions = {
    {x = 0, y = 0, z = 0}, {x = 200, y = 0, z = 0}, {x = 0, y = 200, z = 0},
    {x = 0, y = 0, z = 200}, {x = 150, y = 150, z = 150}, {x = 180, y = 40, z = -120}
  }
  local points = {}
  for i, h in ipairs(hostPositions) do
    local d = math.sqrt((truth.x - h.x) ^ 2 + (truth.y - h.y) ^ 2 + (truth.z - h.z) ^ 2)
    points[i] = {x = h.x, y = h.y, z = h.z, d = d}
  end
  local function copyPoints(n)
    local out = {}
    for i = 1, n do
      out[i] = {x = points[i].x, y = points[i].y, z = points[i].z, d = points[i].d}
    end
    return out
  end
  local function isTruth(x, y, z)
    return x and math.abs(x - truth.x) < 0.01 and math.abs(y - truth.y) < 0.01 and
      math.abs(z - truth.z) < 0.01
  end

  local x, y, z = trilaterate({points[1], points[2], points[3], points[4]})
  check("exact trilateration", isTruth(x, y, z))

  check("clean over-determined set solves", isTruth(sgps.solveWithOutlierRejection(copyPoints(6), 4)))

  -- minFixes + 2 points: one liar can be identified, because the five hosts
  -- left after dropping it still have a redundant measurement to agree on.
  local withOutlier = copyPoints(6)
  withOutlier[5].d = withOutlier[5].d + 500
  check("outlier rejection with a spare host", isTruth(sgps.solveWithOutlierRejection(withOutlier, 4)))

  -- Same liar, same geometry, one fewer host: now unresolvable. It must SAY so
  -- rather than drop a host on a coin flip and return a confident wrong answer.
  local tooFewToJudge = copyPoints(5)
  tooFewToJudge[5].d = tooFewToJudge[5].d + 500
  local x2b, _, _, err2b = sgps.solveWithOutlierRejection(tooFewToJudge, 4)
  check("inconsistent set with no spare host is refused, not guessed at",
    x2b == nil and err2b == "inconsistent_hosts")

  -- Two liars out of six: no single exclusion reconciles the rest.
  local twoLiars = copyPoints(6)
  twoLiars[5].d = twoLiars[5].d + 500
  twoLiars[6].d = twoLiars[6].d - 300
  local x2c, _, _, err2c = sgps.solveWithOutlierRejection(twoLiars, 4)
  check("two bad hosts out of six reported, not resolved",
    x2c == nil and err2c == "too_many_outliers")

  local x3, _, _, err3 = trilaterate({points[1], points[2], points[3]})
  check("insufficient points rejected", x3 == nil and err3 == "insufficient_points")

  local fakePublicKey = {n = "abcd", e = "10001"}
  local request, nonce, responseKey = buildRequest(fakePublicKey)
  local response, meta, reqErr = handleRequestOnHost(request, {x = 12, y = 34, z = -56})
  local parsed, parseErr = parseResponse(response, nonce)
  check("request/response round trip",
    reqErr == nil and meta and meta.clientPublic.n == "abcd" and
    parsed and parsed.x == 12 and parsed.y == 34 and parsed.z == -56)

  check("request carries a v2 responseKey and a distinct nonce",
    isHexString(responseKey, 32) and isHexString(nonce, 32) and responseKey ~= nonce and
    meta.responseKey == responseKey and meta.clientVersion == 2)

  -- Fresh key per request is the one rule that cannot slip: two RC4 messages
  -- under one key XOR into each other's plaintext.
  local seen = {}
  local keyReuse = false
  for _ = 1, 50 do
    local _, n2, k2 = buildRequest(fakePublicKey)
    if seen[k2] or seen[n2] then keyReuse = true end
    seen[k2], seen[n2] = true, true
  end
  check("responseKey is fresh per request (50 requests, no repeats)", not keyReuse)

  local staleResponse = serialize({type = "LOCATE_RESPONSE", nonce = "old-nonce", x = 1, y = 2, z = 3})
  local _, staleErr = parseResponse(staleResponse, nonce)
  check("stale/mismatched nonce rejected", staleErr == "invalid_or_stale_response")

  local _, _, malformedErr = handleRequestOnHost("not even serialized data", {x = 0, y = 0, z = 0})
  check("malformed request rejected", malformedErr == "malformed_request")

  local idRequest = buildIdentifyRequest()
  local idReply = handleIdentifyRequestOnHost(idRequest, fakePublicKey)
  local idKey, idErr = parseIdentifyResponse(idReply)
  check("identify round trip", idErr == nil and idKey.n == "abcd")

  local _, badIdErr = handleIdentifyRequestOnHost("garbage", fakePublicKey)
  check("malformed identify request rejected", badIdErr == "malformed_request")

  local badKeyReply = serialize({type = "IDENTIFY_RESPONSE", publicKey = {n = "not hex", e = "10001"}})
  local _, badKeyErr = parseIdentifyResponse(badKeyReply)
  check("identify response with a junk public key rejected",
    badKeyErr == "malformed_public_key")

  -- ---- symmetric response path (protocol v2) ------------------------------
  -- Pure cipher layer first, so a framing failure below is unambiguous.
  local symKey = random16Hex()
  local symFrame = symEncrypt(symKey, "the quick brown fox")
  check("symmetric frame round trip",
    symFrame.sv == 2 and symDecrypt(symKey, symFrame) == "the quick brown fox")

  local wrongKeyPlain, wrongKeyErr = symDecrypt(random16Hex(), symFrame)
  check("symmetric frame under the wrong key is rejected, not returned as garbage",
    wrongKeyPlain == nil and wrongKeyErr == "bad_tag")

  local tampered = {sv = symFrame.sv, data = symFrame.data, tag = symFrame.tag}
  -- Flip one bit of one ciphertext byte: RC4 alone would hand back a plaintext
  -- with the same bit flipped, which is exactly the attack the tag exists for.
  local firstByte = tonumber(tampered.data:sub(1, 2), 16)
  tampered.data = string.format("%02x", bit32.bxor(firstByte, 1)) .. tampered.data:sub(3)
  local tamperedPlain, tamperedErr = symDecrypt(symKey, tampered)
  check("bit-flipped ciphertext caught by the keyed tag",
    tamperedPlain == nil and tamperedErr == "bad_tag")

  local shortKeyPlain, shortKeyErr = symDecrypt("abcd", symFrame)
  check("undersized symmetric key rejected", shortKeyPlain == nil and shortKeyErr == "no_response_key")

  local junkPlain, junkErr = symDecrypt(symKey, {sv = 2, data = "zzzz", tag = symFrame.tag})
  check("non-hex frame body rejected without throwing",
    junkPlain == nil and junkErr == "malformed_frame")

  -- ---- end to end, with a real keypair ------------------------------------
  -- 192 bits is enc.lua's minimum and the fastest key it will make; this test
  -- is about the protocol, not about key strength.
  local pub, priv = enc.generateKeyPair(192)

  -- v2 client -> v2 host -> v2 client. The host does one RSA private op to read
  -- the request; the reply costs neither side any RSA at all.
  local hostPos = {x = -300, y = 71, z = 1024}
  local v2Request, v2Nonce, v2Key = buildRequest(pub)
  local onWire = enc.encrypt(pub, v2Request)               -- client -> host
  local v2Plain = enc.decrypt(priv, onWire)                -- host reads it
  local v2Response, v2Meta, v2Err = handleRequestOnHost(v2Plain, hostPos)
  local v2Package, v2Mode = sealResponse(v2Response, v2Meta)
  local v2Message, v2OpenErr, v2OpenMode = openResponse(v2Package, v2Key, priv)
  local v2Parsed = v2Message and parseResponse(v2Message, v2Nonce)
  check("v2 end to end: symmetric reply, no client RSA private op",
    v2Err == nil and v2Mode == "symmetric" and v2Package.sv == 2 and
    v2Package.key == nil and v2OpenErr == nil and v2OpenMode == "symmetric" and
    v2Parsed and v2Parsed.x == -300 and v2Parsed.y == 71 and v2Parsed.z == 1024 and
    v2Parsed.nonce == v2Nonce)

  -- A v2 client must reject a symmetric reply keyed to somebody else's request:
  -- that covers both a replayed old frame and one from an attacker who guessed.
  local otherKeyMessage, otherKeyErr = openResponse(v2Package, random16Hex(), priv)
  check("v2 reply for a different responseKey rejected",
    otherKeyMessage == nil and otherKeyErr == "bad_tag")

  -- A recorded v2 frame replayed against a later request: the tag verifies
  -- (same key, unmodified) but the nonce inside no longer matches.
  local _, laterNonce = buildRequest(pub)
  local replayMessage = openResponse(v2Package, v2Key, priv)
  local replayParsed, replayErr = parseResponse(replayMessage, laterNonce)
  check("replayed v2 reply fails the nonce check",
    replayParsed == nil and replayErr == "invalid_or_stale_response")

  -- v1 client (no responseKey) -> v2 host: must still get a valid RSA reply, so
  -- an upgraded host keeps serving clients that haven't been upgraded yet.
  local v1Nonce = randomNonce()
  local v1Request = serialize({type = "LOCATE_REQUEST", nonce = v1Nonce, clientPublic = pub})
  local v1Response, v1Meta, v1Err = handleRequestOnHost(v1Request, hostPos)
  local v1Package, v1Mode = sealResponse(v1Response, v1Meta)
  local v1Message, v1OpenErr, v1OpenMode = openResponse(v1Package, nil, priv)
  local v1Parsed = v1Message and parseResponse(v1Message, v1Nonce)
  check("legacy v1 request (no responseKey) still gets a valid RSA reply",
    v1Err == nil and v1Meta.responseKey == nil and v1Meta.clientVersion == 1 and
    v1Mode == "rsa" and v1Package.key ~= nil and v1Package.sv == nil and
    v1OpenErr == nil and v1OpenMode == "rsa" and
    v1Parsed and v1Parsed.x == -300 and v1Parsed.y == 71 and v1Parsed.z == 1024)

  -- ...and a v1 host answering a v2 client: the host ignores responseKey it
  -- doesn't understand and replies by RSA. Simulated by sealing the v2 request's
  -- response with the responseKey stripped out, which is what v1 code did.
  local mixedResponse, mixedMeta = handleRequestOnHost(v2Request, hostPos)
  local v1StyleReply = sealResponse(mixedResponse,
    {clientPublic = mixedMeta.clientPublic})
  local mixedMessage, mixedErr, mixedMode = openResponse(v1StyleReply, v2Key, priv)
  check("v2 client accepts an RSA reply from a v1 host",
    mixedErr == nil and mixedMode == "rsa" and mixedMessage ~= nil and
    parseResponse(mixedMessage, v2Nonce) ~= nil)

  local badResponseKeyRequest = serialize({
    type = "LOCATE_REQUEST", v = 2, nonce = randomNonce(),
    responseKey = "not-a-hex-key", clientPublic = pub
  })
  local _, _, badKeyReqErr = handleRequestOnHost(badResponseKeyRequest, hostPos)
  check("request with a malformed responseKey rejected",
    badKeyReqErr == "malformed_request")

  local noKeyRequest = serialize({type = "LOCATE_REQUEST", nonce = randomNonce()})
  local _, _, noKeyErr = handleRequestOnHost(noKeyRequest, hostPos)
  check("unanswerable request (no responseKey and no client key) rejected",
    noKeyErr == "malformed_request")

  -- ---- preflight ----------------------------------------------------------
  -- Modem selection can't be exercised without hardware, but the loud-failure
  -- path can: opening a side with nothing on it must say so, not bind blindly.
  local openOk, openErr = pcall(sgps.open, "no_such_side")
  check("sgps.open on an empty side fails with a readable message",
    not openOk and type(openErr) == "string" and
    openErr:find("nothing attached", 1, true) ~= nil)

  print(allPassed and "SELF TEST PASSED" or "SELF TEST FAILED")
  return allPassed
end

local progArgs = {...}
if progArgs[1] == "test" then
  sgps.selfTest()
end

return sgps
