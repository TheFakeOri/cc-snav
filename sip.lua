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
  yourself if you've loaded it some other way).

  SECURITY NOTE: inherits every caveat from enc.lua (toy RSA, RC4, weak
  randomness - see enc.lua's header). The per-message checksum here is a
  plain non-cryptographic checksum, not a MAC: it catches accidental
  corruption and naive tampering, but a determined attacker who can control
  ciphertext bits is not cryptographically prevented from forging one.
  Sequence numbers reject exact replays and older messages, but are only
  tracked in memory - if a peer reboots, re-run the handshake with it
  before trusting its sequence numbers again. Treat this as good-enough
  privacy between friendly computers on a shared network, not a hardened
  protocol.

  Usage:
    local sip = dofile("sip.lua")

    sip.generateIdentity(256)      -- or sip.loadIdentity(pubPath, privPath, pass)
    sip.open("back")               -- opens the modem on the given side

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

local function loadEnc()
  local dir = getScriptDir()
  local candidates = {}
  if dir then candidates[#candidates + 1] = dir .. "enc.lua" end
  candidates[#candidates + 1] = "enc.lua"
  candidates[#candidates + 1] = "/enc.lua"
  for _, path in ipairs(candidates) do
    if fs.exists(path) then return dofile(path) end
  end
  error("sip.lua: could not locate enc.lua. Place it next to sip.lua, " ..
    "or load it yourself and call sip.useEnc(encModule).", 2)
end

local enc = loadEnc()

-- lets callers swap in an already-loaded enc module, e.g. in tests or
-- non-standard directory layouts
function sip.useEnc(mod) enc = mod end

sip.PROTOCOL = "sip"
sip.HELLO_PROTOCOL = "sip_hello"

local state = {
  identity = nil, -- {public = <table>, private = <table>}
  peers = {}      -- [rednetId] = {public=, sendSeq=, lastRecvSeq=}
}

-- ===========================================================================
-- Identity
-- ===========================================================================

function sip.generateIdentity(bits)
  local public, private = enc.generateKeyPair(bits or 256)
  state.identity = {public = public, private = private}
  return public, private
end

function sip.saveIdentity(publicPath, privatePath, passphrase)
  assert(state.identity, "sip: no identity to save; call sip.generateIdentity first")
  enc.savePlain(publicPath, state.identity.public)
  enc.saveEncrypted(privatePath, state.identity.private, passphrase)
end

function sip.loadIdentity(publicPath, privatePath, passphrase)
  local public = enc.loadPlain(publicPath)
  local private = enc.loadEncrypted(privatePath, passphrase)
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
-- raw encrypt/decrypt without going through sip's rednet-based transport
function sip.getEnc() return enc end

-- ===========================================================================
-- Peer directory
-- ===========================================================================

function sip.setPeerPublicKey(peerId, publicKey)
  state.peers[peerId] = state.peers[peerId] or {}
  state.peers[peerId].public = publicKey
end

function sip.getPeerPublicKey(peerId)
  local peer = state.peers[peerId]
  return peer and peer.public
end

function sip.listPeers()
  local ids = {}
  for id in pairs(state.peers) do ids[#ids + 1] = id end
  return ids
end

-- ===========================================================================
-- Transport setup
-- ===========================================================================

function sip.open(modemSide)
  if not modemSide then
    for _, side in ipairs(peripheral.getNames()) do
      if peripheral.getType(side) == "modem" then
        modemSide = side
        break
      end
    end
    assert(modemSide, "sip.open: no modemSide given and no modem peripheral attached")
  end
  rednet.open(modemSide)
end

function sip.close(modemSide) rednet.close(modemSide) end

-- ===========================================================================
-- Handshake: exchanging public keys over rednet
-- ===========================================================================

local function buildHello(kind)
  assert(state.identity, "sip: no identity set; call sip.generateIdentity/sip.loadIdentity first")
  return {type = kind, public = state.identity.public}
end

function sip.broadcastIdentity()
  rednet.broadcast(buildHello("HELLO"), sip.HELLO_PROTOCOL)
end

-- Sends our public key to peerId and waits for theirs. Returns the peer's
-- public key, or nil on timeout.
function sip.requestIdentity(peerId, timeout)
  rednet.send(peerId, buildHello("HELLO_REQUEST"), sip.HELLO_PROTOCOL)
  local deadline = os.clock() + (timeout or 3)
  while true do
    local remaining = deadline - os.clock()
    if remaining <= 0 then return nil end
    local senderId, msg = rednet.receive(sip.HELLO_PROTOCOL, remaining)
    if senderId == peerId and type(msg) == "table" and msg.public then
      sip.setPeerPublicKey(senderId, msg.public)
      return msg.public
    end
  end
end

-- Run this in parallel with your program (e.g. via parallel.waitForAny) to
-- keep learning peers' public keys and auto-answering their requests.
function sip.listenForHandshakes()
  while true do
    local senderId, msg = rednet.receive(sip.HELLO_PROTOCOL)
    if type(msg) == "table" and msg.public and
       (msg.type == "HELLO" or msg.type == "HELLO_REQUEST") then
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

local function checksum(s)
  local sum = 0
  for i = 1, #s do
    sum = (sum + s:byte(i) * i) % 65536
  end
  return string.format("%04x", sum)
end

local function encodePayload(seq, message)
  local payload = tostring(seq) .. "|" .. message
  return checksum(payload) .. ":" .. payload
end

local function decodePayload(framed)
  local chk, payload = framed:match("^(%x%x%x%x):(.*)$")
  if not chk or checksum(payload) ~= chk then return nil, "integrity_check_failed" end
  local seqStr, message = payload:match("^(%d+)|(.*)$")
  if not seqStr then return nil, "malformed_payload" end
  return tonumber(seqStr), message
end

-- Pure helpers (no rednet) so the crypto/framing/replay logic can be unit
-- tested without a modem. Exposed for sip.selfTest(); not part of the
-- stable public API.
sip._internal = {}

function sip._internal.buildEnvelope(peer, peerPublicKey, message)
  peer.sendSeq = (peer.sendSeq or 0) + 1
  local framed = encodePayload(peer.sendSeq, message)
  return {package = enc.encrypt(peerPublicKey, framed)}, peer.sendSeq
end

function sip._internal.openEnvelope(myPrivateKey, peer, envelope)
  if type(envelope) ~= "table" or not envelope.package then
    return nil, nil, "malformed"
  end
  local ok, framed = pcall(enc.decrypt, myPrivateKey, envelope.package)
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
  rednet.send(peerId, envelope, sip.PROTOCOL)
  return seq
end

-- Returns senderId, message, seq on success, or nil, err on failure/timeout.
function sip.receive(timeout)
  assert(state.identity, "sip: no identity set")
  local senderId, envelope = rednet.receive(sip.PROTOCOL, timeout)
  if senderId == nil then return nil, "timeout" end

  state.peers[senderId] = state.peers[senderId] or {}
  local seq, message, err = sip._internal.openEnvelope(state.identity.private, state.peers[senderId], envelope)
  if not seq then return nil, err end
  return senderId, message, seq
end

-- ===========================================================================
-- Self-test: exercises encryption, framing, tamper detection and replay
-- rejection directly, without needing real rednet hardware.
-- ===========================================================================

function sip.selfTest(bits)
  bits = bits or 256
  print("Generating two " .. bits .. "-bit identities (may take a few seconds)...")

  local aPub, aPriv = enc.generateKeyPair(bits)
  local bPub, bPriv = enc.generateKeyPair(bits)

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

  print(allPassed and "SELF TEST PASSED" or "SELF TEST FAILED")
  return allPassed
end

local progArgs = {...}
if progArgs[1] == "test" then
  sip.selfTest(tonumber(progArgs[2]) or 256)
end

return sip
