--[[
  sip.lua - Secure Information Protocol: a rednet-based secure messaging
  layer built on top of enc.lua's RSA/RC4 hybrid encryption.

  enc.lua only knows how to encrypt/decrypt one message given a keypair.
  sip.lua adds everything a real conversation over rednet needs on top of
  that:
    - identity: generate/save/load a computer's own RSA keypair
    - handshake: broadcast/request public keys so peers can find each other
    - framing: an integrity checksum + per-peer sequence numbers, so
      corrupted or replayed packets are rejected instead of silently
      decrypted to garbage
    - transport: thin wrappers around rednet.send/rednet.receive

  Requires enc.lua in the same directory (or call sip.useEnc(encModule)
  yourself if you've loaded it some other way). enc.lua is only read on
  first actual use, so a caller that supplies its own copy via
  sip.useEnc() never pays to parse it.

  SECURITY NOTE: inherits every caveat from enc.lua (toy RSA, RC4, weak
  randomness - see enc.lua's header). The per-message checksum here is a
  plain non-cryptographic checksum, not a MAC: it catches accidental
  corruption and naive tampering, but a determined attacker who can control
  ciphertext bits is not cryptographically prevented from forging one.
  Sequence numbers reject exact replays and older messages, but are only
  tracked in memory. A peer that reboots restarts its sequence numbers at 1
  while we still remember its old high-water mark, so everything it sends
  looks like a replay: call sip.forgetPeer(id) (or reboot) and re-handshake.
  A peer that comes back with a *different* public key is detected and reset
  automatically. Treat this as good-enough privacy between friendly
  computers on a shared network, not a hardened protocol.

  Usage:
    local sip = dofile("sip.lua")

    sip.generateIdentity(256)      -- or sip.loadIdentity(pubPath, privPath, pass)
    sip.open()                     -- picks a wireless modem, or sip.open("back")

    -- learn about peers (run in parallel with your own program):
    parallel.waitForAny(sip.listenForHandshakes, function()
      sip.broadcastIdentity()
      sleep(2)

      sip.send(otherComputerId, "hello!")
      local senderId, message = sip.receive(5)
      print(senderId, message)
    end)

  Run `sip.lua test` from the shell to exercise the crypto/framing/replay
  logic directly (no modem required).
]]

local sip = {}

-- Hoisted out of the hot path: checksum() touches every byte of every
-- message, and encode/decodePayload run once per send and per receive.
-- string.byte(s, i) also skips the string-metatable lookup that s:byte(i)
-- pays on every call.
local sbyte, sformat, smatch = string.byte, string.format, string.match

local function getScriptDir()
  -- must forward args to debug.getinfo directly (not via a wrapper
  -- closure) for the level count to land on this function's own frame,
  -- whose source is this file (sip.lua)
  local ok, info = pcall(debug.getinfo, 2, "S")
  if ok and info and info.source then
    local path = info.source:match("^@(.*)$") or info.source
    local dir = path:match("^(.*)[/\\][^/\\]*$")
    if dir and dir ~= "" then return dir .. "/" end
  end
  return nil
end

-- enc.lua is over a thousand lines of bignum arithmetic and is not cheap to
-- parse. sGps dofile's sip.lua and sNav dofile's both, so a top-level
-- `local enc = loadEnc()` used to read and run enc.lua several times per ship
-- boot - including once for a sip instance that useSip()/useEnc() discards a
-- moment later. Two things stop that:
--
--   * enc is resolved on first real use (see getEnc), so sip.useEnc(mod)
--     before any crypto call means enc.lua is never touched at all;
--   * the loaded module is memoised against its resolved path in a global,
--     so sibling sip instances inside one program share a single copy - and
--     with it enc's per-key Montgomery/hex context caches.
--
-- The global is read and written with rawget/rawset so it stays invisible to
-- bios.strict_globals.
local ENC_REGISTRY = "__sip_enc_modules"

local function encRegistry()
  local reg = rawget(_G, ENC_REGISTRY)
  if type(reg) ~= "table" then
    reg = {}
    rawset(_G, ENC_REGISTRY, reg)
  end
  return reg
end

local function loadEnc()
  local dir = getScriptDir()
  local candidates = {}
  if dir then candidates[#candidates + 1] = dir .. "enc.lua" end
  candidates[#candidates + 1] = "enc.lua"
  candidates[#candidates + 1] = "/enc.lua"
  local reg = encRegistry()
  for _, path in ipairs(candidates) do
    if fs.exists(path) then
      local key = fs.combine("/", path) -- so "enc.lua" and "/enc.lua" share an entry
      local cached = reg[key]
      if cached then return cached end
      local mod = dofile(path)
      if type(mod) ~= "table" or type(mod.encrypt) ~= "function" then
        error("sip.lua: " .. path .. " did not return an enc module (expected a table " ..
          "with encrypt/decrypt). Load it yourself and call sip.useEnc(encModule).", 0)
      end
      reg[key] = mod
      return mod
    end
  end
  error("sip.lua: could not locate enc.lua. Place it next to sip.lua, " ..
    "or load it yourself and call sip.useEnc(encModule).", 0)
end

local enc = nil -- resolved lazily; every internal use goes through getEnc()

local function getEnc()
  local mod = enc
  if not mod then
    mod = loadEnc()
    enc = mod
  end
  return mod
end

-- lets callers swap in an already-loaded enc module, e.g. in tests or
-- non-standard directory layouts. Call this before any crypto and enc.lua is
-- never read.
function sip.useEnc(mod)
  assert(type(mod) == "table", "sip.useEnc: expected the enc module table")
  enc = mod
end

sip.PROTOCOL = "sip"
sip.HELLO_PROTOCOL = "sip_hello"

local state = {
  identity = nil,  -- {public = <table>, private = <table>}
  peers = {},      -- [rednetId] = {public=, sendSeq=, lastRecvSeq=}
  modemSide = nil  -- whatever sip.open() bound rednet to
}

-- ===========================================================================
-- Identity
-- ===========================================================================

function sip.generateIdentity(bits)
  local public, private = getEnc().generateKeyPair(bits or 256)
  state.identity = {public = public, private = private}
  return public, private
end

function sip.saveIdentity(publicPath, privatePath, passphrase)
  assert(state.identity, "sip: no identity to save; call sip.generateIdentity first")
  local e = getEnc()
  e.savePlain(publicPath, state.identity.public)
  e.saveEncrypted(privatePath, state.identity.private, passphrase)
end

function sip.loadIdentity(publicPath, privatePath, passphrase)
  local e = getEnc()
  local public = e.loadPlain(publicPath)
  assert(type(public) == "table" and public.n and public.e,
    "sip: could not load public key from " .. tostring(publicPath) ..
    " (missing or corrupt file)")
  local private = e.loadEncrypted(privatePath, passphrase)
  assert(private, "sip: could not load private key (missing file or wrong passphrase)")
  state.identity = {public = public, private = private}
  return public, private
end

function sip.getPublicKey()
  assert(state.identity, "sip: no identity set")
  return state.identity.public
end

function sip.getPrivateKey()
  assert(state.identity, "sip: no identity set")
  return state.identity.private
end

function sip.getMyId() return os.getComputerID() end

-- exposes the underlying enc.lua module, for code (like sGps) that needs
-- raw encrypt/decrypt without going through sip's rednet-based transport.
-- Loads enc.lua if nothing has needed it yet.
function sip.getEnc() return getEnc() end

-- ===========================================================================
-- Peer directory
-- ===========================================================================

local function sameKey(a, b)
  return type(a) == "table" and type(b) == "table" and a.n == b.n and a.e == b.e
end

function sip.setPeerPublicKey(peerId, publicKey)
  local peer = state.peers[peerId]
  if not peer then
    peer = {}
    state.peers[peerId] = peer
  elseif peer.public ~= nil and not sameKey(peer.public, publicKey) then
    -- A different key is a different identity, so the sequence counters we
    -- were tracking belong to a conversation that no longer exists; keeping
    -- them would make every message from the new key look like a replay.
    -- Note this only fires on an actual key change - re-broadcasting a peer's
    -- existing HELLO cannot be used to clear our replay window.
    peer.sendSeq, peer.lastRecvSeq = nil, nil
  end
  peer.public = publicKey
end

function sip.getPeerPublicKey(peerId)
  local peer = state.peers[peerId]
  return peer and peer.public
end

-- Drops everything known about a peer, sequence counters included. Needed
-- when a peer reboots with the *same* saved identity: its sendSeq restarts at
-- 1 while our lastRecvSeq is still high, so every message it sends is
-- rejected as a replay until one side forgets the other.
function sip.forgetPeer(peerId)
  state.peers[peerId] = nil
end

function sip.listPeers()
  local ids = {}
  for id in pairs(state.peers) do ids[#ids + 1] = id end
  return ids
end

-- ===========================================================================
-- Transport setup
-- ===========================================================================

-- hasType is 1.99+ and is the right test, because one block can carry several
-- peripheral types and getType() then returns more than just "modem".
local function isModem(name)
  if type(name) ~= "string" then return false end
  if peripheral.hasType then return peripheral.hasType(name, "modem") == true end
  return peripheral.getType(name) == "modem"
end

-- Returns name, isWireless for the best modem attached, or nil.
--
-- peripheral.getNames() order is arbitrary, so "the first modem" is frequently
-- the wired one on any base with wired networking - rednet then binds to a
-- cable that no wireless ship is on, which looks exactly like "my messages
-- never arrive". isWireless() is pcall'd because the block can be broken
-- between getNames() and the call.
local function findModem()
  local wired
  for _, name in ipairs(peripheral.getNames()) do
    if isModem(name) then
      local ok, wireless = pcall(peripheral.call, name, "isWireless")
      if ok and wireless then return name, true end
      if not wired then wired = name end
    end
  end
  if wired then return wired, false end
  return nil
end

sip.findModem = findModem

-- Binds rednet to a modem. With no argument, prefers wireless/ender over
-- wired. Returns the name it bound to.
function sip.open(modemSide)
  local wireless = true
  if modemSide == nil then
    modemSide, wireless = findModem()
    if not modemSide then
      error("sip.open: no modem attached. Put a wireless (or ender) modem on any " ..
        "side of this computer, or name one explicitly: sip.open(\"back\").", 0)
    end
  elseif not isModem(modemSide) then
    error("sip.open: '" .. tostring(modemSide) .. "' is not a modem. Attach one " ..
      "there, or call sip.open() with no argument to pick one automatically.", 0)
  end
  if not wireless then
    print("sip.open: no wireless modem found; using wired modem '" .. modemSide ..
      "'. Only peers on that cable network are reachable.")
  end
  rednet.open(modemSide)
  state.modemSide = modemSide
  return modemSide
end

function sip.close(modemSide)
  modemSide = modemSide or state.modemSide
  if modemSide then rednet.close(modemSide) else rednet.close() end
  state.modemSide = nil
end

function sip.getModemSide() return state.modemSide end

-- ===========================================================================
-- Handshake: exchanging public keys over rednet
-- ===========================================================================

local function buildHello(kind)
  assert(state.identity, "sip: no identity set; call sip.generateIdentity/sip.loadIdentity first")
  return {type = kind, public = state.identity.public}
end

-- rednet.receive() starts a timer and never cancels it when a message
-- arrives, so any loop that calls it repeatedly - a handshake waiting for one
-- specific sender, say - drips orphaned timers into the 256-slot event queue.
-- It also has no way to say "not that sender, keep waiting on the same
-- deadline", so a chatty network makes its timeout unbounded. One timer for
-- the whole wait, cancelled on the way out, fixes both.
--
-- accept(senderId, message) returns truthy to take the message. Returns
-- senderId, message, or nil on timeout. Like rednet.receive, events that are
-- not rednet messages are discarded while we wait, so run this in its own
-- parallel task if the program also needs keys or redstone.
local function receiveMatching(protocol, timeout, accept)
  local timer, filter = nil, "rednet_message"
  if timeout then
    timer = os.startTimer(timeout)
    filter = nil -- must see our own timer, so nothing can be filtered out
  end
  while true do
    local event, p1, p2, p3 = os.pullEvent(filter)
    if event == "rednet_message" then
      if (protocol == nil or p3 == protocol) and (accept == nil or accept(p1, p2)) then
        if timer then os.cancelTimer(timer) end
        return p1, p2
      end
    elseif event == "timer" and timer ~= nil and p1 == timer then
      return nil
    end
  end
end

local function acceptHello(_, msg)
  return type(msg) == "table" and msg.public ~= nil
end

-- Returns true if the broadcast went out, or false, "rednet_not_open" if no
-- modem is open (rednet.broadcast swallows that, so it looks like success).
function sip.broadcastIdentity()
  local hello = buildHello("HELLO") -- built first: asserts before anything is sent
  if not rednet.send(rednet.CHANNEL_BROADCAST, hello, sip.HELLO_PROTOCOL) then
    return false, "rednet_not_open"
  end
  return true
end

-- Sends our public key to peerId and waits for theirs. Returns the peer's
-- public key, or nil plus a reason on failure.
function sip.requestIdentity(peerId, timeout)
  local hello = buildHello("HELLO_REQUEST")
  if not rednet.send(peerId, hello, sip.HELLO_PROTOCOL) then
    return nil, "rednet_not_open"
  end
  local deadline = os.clock() + (timeout or 3)
  while true do
    local remaining = deadline - os.clock()
    if remaining <= 0 then return nil, "timeout" end
    local senderId, msg = receiveMatching(sip.HELLO_PROTOCOL, remaining, acceptHello)
    if senderId == nil then return nil, "timeout" end
    -- Learn from every valid HELLO that lands here, not just the one we asked
    -- for; otherwise waiting on one peer throws away another peer's key.
    sip.setPeerPublicKey(senderId, msg.public)
    if senderId == peerId then return msg.public end
  end
end

-- Run this in parallel with your program (e.g. via parallel.waitForAny) to
-- keep learning peers' public keys and auto-answering their requests.
function sip.listenForHandshakes()
  while true do
    local senderId, msg = receiveMatching(sip.HELLO_PROTOCOL, nil, acceptHello)
    if senderId and (msg.type == "HELLO" or msg.type == "HELLO_REQUEST") then
      sip.setPeerPublicKey(senderId, msg.public)
      if msg.type == "HELLO_REQUEST" and state.identity then
        rednet.send(senderId, buildHello("HELLO"), sip.HELLO_PROTOCOL)
      end
    end
  end
end

-- ===========================================================================
-- Message framing: checksum + sequence number, wrapped inside the
-- encrypted plaintext (so tampering/replay checks happen after decryption
-- and can't be spoofed by mangling ciphertext alone).
-- ===========================================================================

-- THE VALUE THIS RETURNS IS ON THE WIRE. Both ends must agree on it, so the
-- arithmetic below is deliberately equivalent, byte for byte, to the obvious
-- `sum = (sum + s:byte(i) * i) % 65536` per byte:
--
--   * (a + b) % m == ((a % m) + b) % m, so folding the modulus in only once
--     per block is exact, not approximate;
--   * a block is 8192 bytes, which keeps the running sum inside a double's
--     exact integer range (255 * 8192 * #s stays far below 2^53 for any
--     message rednet can carry), so nothing rounds.
--
-- Localising string.byte and dropping ~8191 of every 8192 modulo operations is
-- worth doing because this runs per byte of every message sent and received.
local CHECKSUM_BLOCK = 8192

local function checksum(s)
  local n = #s
  local sum = 0
  local i = 1
  while i <= n do
    local stop = i + CHECKSUM_BLOCK - 1
    if stop > n then stop = n end
    for j = i, stop do
      sum = sum + sbyte(s, j) * j
    end
    sum = sum % 65536
    i = stop + 1
  end
  return sformat("%04x", sum)
end

local function encodePayload(seq, message)
  local payload = tostring(seq) .. "|" .. message
  return checksum(payload) .. ":" .. payload
end

local function decodePayload(framed)
  if type(framed) ~= "string" then return nil, "integrity_check_failed" end
  -- One pass for the good case: nested captures hand back the checksum, the
  -- payload it covers, and the payload's two fields together, instead of
  -- matching and copying the string twice.
  local chk, payload, seqStr, message = smatch(framed, "^(%x%x%x%x):((%d+)|(.*))$")
  if chk then
    if checksum(payload) ~= chk then return nil, "integrity_check_failed" end
    return tonumber(seqStr), message
  end
  -- Something is wrong; work out which error to report. Only reached for
  -- corrupt or hostile input, so the second match costs nothing in practice.
  local badChk, badPayload = smatch(framed, "^(%x%x%x%x):(.*)$")
  if not badChk or checksum(badPayload) ~= badChk then
    return nil, "integrity_check_failed"
  end
  return nil, "malformed_payload"
end

-- Pure helpers (no rednet) so the crypto/framing/replay logic can be unit
-- tested without a modem. Exposed for sip.selfTest(); not part of the
-- stable public API.
sip._internal = {
  checksum = checksum,
  encodePayload = encodePayload,
  decodePayload = decodePayload
}

function sip._internal.buildEnvelope(peer, peerPublicKey, message)
  peer.sendSeq = (peer.sendSeq or 0) + 1
  local framed = encodePayload(peer.sendSeq, message)
  return {package = getEnc().encrypt(peerPublicKey, framed)}, peer.sendSeq
end

function sip._internal.openEnvelope(myPrivateKey, peer, envelope)
  if type(envelope) ~= "table" or not envelope.package then
    return nil, nil, "malformed"
  end
  local ok, framed = pcall(getEnc().decrypt, myPrivateKey, envelope.package)
  if not ok then return nil, nil, "decrypt_failed" end

  local seq, message = decodePayload(framed)
  if not seq then return nil, nil, message end

  if peer.lastRecvSeq and seq <= peer.lastRecvSeq then
    return nil, nil, "replay"
  end
  peer.lastRecvSeq = seq
  return seq, message, nil
end

-- ===========================================================================
-- Secure send/receive
-- ===========================================================================

function sip.send(peerId, message)
  assert(state.identity, "sip: no identity set")
  assert(type(message) == "string", "sip.send: message must be a string")
  local peer = state.peers[peerId]
  assert(peer and peer.public, "sip.send: no public key known for peer " ..
    tostring(peerId) .. "; call sip.requestIdentity first")

  local envelope, seq = sip._internal.buildEnvelope(peer, peer.public, message)
  envelope.from = sip.getMyId()
  -- rednet.send returns false when no modem is open - the usual cause is a
  -- forgotten sip.open(), or a modem that was broken since. The sequence
  -- number stays consumed: the receiver only requires seq to increase, so a
  -- gap is harmless, whereas reusing one would look like a replay.
  if not rednet.send(peerId, envelope, sip.PROTOCOL) then
    return nil, "rednet_not_open"
  end
  return seq
end

-- Returns senderId, message, seq on success, or nil, err on failure/timeout.
function sip.receive(timeout)
  assert(state.identity, "sip: no identity set")
  local senderId, envelope = receiveMatching(sip.PROTOCOL, timeout, nil)
  if senderId == nil then return nil, "timeout" end

  -- Anyone on the network can address us, so the peer record is only kept
  -- once a message from this sender has actually verified. Allocating one up
  -- front let a stranger grow state.peers (and sip.listPeers) with garbage.
  local peer = state.peers[senderId] or {}
  local seq, message, err = sip._internal.openEnvelope(state.identity.private, peer, envelope)
  if not seq then return nil, err end
  state.peers[senderId] = peer
  return senderId, message, seq
end

-- ===========================================================================
-- Self-test: exercises encryption, framing, tamper detection and replay
-- rejection directly, without needing real rednet hardware.
-- ===========================================================================

function sip.selfTest(bits)
  bits = bits or 256
  print("Generating two " .. bits .. "-bit identities (may take a few seconds)...")

  local e = getEnc()
  local aPub, aPriv = e.generateKeyPair(bits)
  local bPub, bPriv = e.generateKeyPair(bits)

  local peerAsSeenByA = {public = bPub} -- A's view of B
  local peerAsSeenByB = {public = aPub} -- B's view of A

  local allPassed = true
  local function check(name, ok)
    print((ok and "PASS " or "FAIL ") .. name)
    allPassed = allPassed and ok
  end

  -- 1. normal round trip A -> B
  local envelope1, seq1 = sip._internal.buildEnvelope(peerAsSeenByA, bPub, "hello from A")
  local gotSeq1, message1 = sip._internal.openEnvelope(bPriv, peerAsSeenByB, envelope1)
  check("round trip", gotSeq1 == seq1 and message1 == "hello from A")

  -- 2. tampering with the ciphertext is detected after decryption
  local envelope2 = sip._internal.buildEnvelope(peerAsSeenByA, bPub, "second message")
  local tampered = {package = {key = envelope2.package.key, data = envelope2.package.data}}
  local lastByte = tampered.package.data:sub(-1)
  local flipped = lastByte == "0" and "1" or "0"
  tampered.package.data = tampered.package.data:sub(1, -2) .. flipped
  local seqT, _, errT = sip._internal.openEnvelope(bPriv, peerAsSeenByB, tampered)
  check("tamper detection", seqT == nil and (errT == "integrity_check_failed" or errT == "malformed_payload"))

  -- 3. replaying the same (untampered) envelope is rejected
  local seqR = sip._internal.openEnvelope(bPriv, peerAsSeenByB, envelope2)
  check("first delivery of message 2", seqR ~= nil)
  local seqR2, _, errR2 = sip._internal.openEnvelope(bPriv, peerAsSeenByB, envelope2)
  check("replay rejection", seqR2 == nil and errR2 == "replay")

  -- 4. a peer without the right private key can't read the message
  local envelope4 = sip._internal.buildEnvelope(peerAsSeenByA, bPub, "not for you")
  local seq4 = sip._internal.openEnvelope(aPriv, {public = bPub}, envelope4)
  check("wrong private key can't decrypt", seq4 == nil)

  -- 5. framing on its own, including the cases the envelope path never shows:
  -- a body that survives the checksum but isn't a payload, and the awkward
  -- strings ("" and one containing the separators) that off-by-one framing
  -- bugs hide in.
  local framingOk = true
  for _, case in ipairs({"", "|", "x:y", "a|b:c", ("z"):rep(4096)}) do
    for _, s in ipairs({1, 7, 65535, 1000000}) do
      local gotSeq, gotMsg = decodePayload(encodePayload(s, case))
      if gotSeq ~= s or gotMsg ~= case then framingOk = false end
    end
  end
  check("framing round trip", framingOk)

  local wellFormedButEmpty = checksum("nope") .. ":nope"
  local _, badErr = decodePayload(wellFormedButEmpty)
  check("malformed payload rejected", badErr == "malformed_payload")

  local corrupt = encodePayload(1, "hello"):gsub("|", "!", 1)
  local _, corruptErr = decodePayload(corrupt)
  check("corrupt payload rejected", corruptErr == "integrity_check_failed")

  print(allPassed and "SELF TEST PASSED" or "SELF TEST FAILED")
  return allPassed
end

local progArgs = {...}
if progArgs[1] == "test" then
  sip.selfTest(tonumber(progArgs[2]) or 256)
end

return sip
