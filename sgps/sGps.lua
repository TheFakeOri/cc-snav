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
    - If more hosts than the minimum are pinned and queried, sGps solves
      the position, checks how well each host's claim fits that solution,
      and drops the worst-fitting host as a likely liar/compromised host
      if it's wildly inconsistent with the rest - then re-solves. This
      tolerates a minority of bad hosts among a larger trusted set.

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

  Requires a wireless modem specifically - wired modems report a nil
  distance, which sGps has no use for.

  HONEST LIMITS - read before relying on this for anything:
    - This inherits every caveat from enc.lua/sip.lua: toy RSA, RC4, weak
      randomness, a non-cryptographic integrity checksum. Good enough to
      stop casual spoofing/eavesdropping/replay; not proven against a
      determined attacker.
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

local function findModem()
  for _, side in ipairs(peripheral.getNames()) do
    if peripheral.getType(side) == "modem" then return side end
  end
  return nil
end

function sgps.open(side)
  state.modemSide = side or findModem()
  assert(state.modemSide, "sgps.open: no side given and no modem peripheral attached")
  peripheral.call(state.modemSide, "open", os.getComputerID())
end

function sgps.close()
  if state.modemSide then
    peripheral.call(state.modemSide, "close", os.getComputerID())
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

local function randomNonce()
  local parts = {}
  for i = 1, 16 do parts[i] = string.format("%02x", math.random(0, 255)) end
  return table.concat(parts)
end

-- ===========================================================================
-- Trusted host directory
-- ===========================================================================

function sgps.trustHost(id, publicKey)
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

local function parseIdentifyResponse(payload)
  local response = deserialize(payload)
  if not (type(response) == "table" and response.type == "IDENTIFY_RESPONSE" and response.publicKey) then
    return nil, "malformed_response"
  end
  return response.publicKey, nil
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
  local f = assert(fs.open(path, "w"), "sgps: could not open " .. path)
  f.write(serialize(state.trustedHosts))
  f.close()
end

function sgps.loadTrustedHosts(path)
  local f = assert(fs.open(path, "r"), "sgps: could not open " .. path)
  local data = deserialize(f.readAll())
  f.close()
  state.trustedHosts = data or {}
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

-- Solves for position, dropping at most one host per round whose claim
-- doesn't fit, as long as at least minFixes points remain. Returns
-- x, y, z, nil or nil, nil, nil, err.
--
-- With exactly minFixes points the linear solve is exactly determined, so
-- it fits all of them perfectly even if one is lying - a lone bad point
-- can't be spotted by checking its own residual against a fit it was part
-- of. Instead, when the full set disagrees with itself, each point is
-- tried as the one left OUT: solve on the rest, then check whether the
-- left-out point's claim matches that solution. The honest majority
-- produces a solution the true outlier clearly disagrees with; leaving
-- out an honest point instead still leaves the liar in the mix, which
-- drags that solution far enough off that the left-out (honest) point
-- disagrees even more. Whichever exclusion disagrees least is the liar.
function sgps.solveWithOutlierRejection(points, minFixes)
  minFixes = minFixes or sgps.DEFAULT_MIN_FIXES
  local pts = {}
  for i, p in ipairs(points) do pts[i] = p end

  while true do
    if #pts < minFixes then return nil, nil, nil, "too_many_outliers" end

    local x, y, z, err = trilaterate(pts)
    if not x then return nil, nil, nil, err end

    local worstResidual = 0
    for _, p in ipairs(pts) do
      local predicted = math.sqrt((x - p.x) ^ 2 + (y - p.y) ^ 2 + (z - p.z) ^ 2)
      worstResidual = math.max(worstResidual, math.abs(predicted - p.d))
    end
    if worstResidual <= sgps.MAX_RESIDUAL or #pts <= minFixes then
      return x, y, z, nil
    end

    local bestDrop, bestExcludedResidual = nil, math.huge
    for dropIdx = 1, #pts do
      local subset = {}
      for i, p in ipairs(pts) do
        if i ~= dropIdx then subset[#subset + 1] = p end
      end
      local sx, sy, sz = trilaterate(subset)
      if sx then
        local dropped = pts[dropIdx]
        local predicted = math.sqrt((sx - dropped.x) ^ 2 + (sy - dropped.y) ^ 2 + (sz - dropped.z) ^ 2)
        local excludedResidual = math.abs(predicted - dropped.d)
        if excludedResidual < bestExcludedResidual then
          bestExcludedResidual, bestDrop = excludedResidual, dropIdx
        end
      end
    end

    if not bestDrop then return nil, nil, nil, "too_many_outliers" end
    table.remove(pts, bestDrop)
  end
end

-- ===========================================================================
-- Request/response framing (pure, testable independent of rednet)
-- ===========================================================================

local function buildRequest(myPublicKey)
  local nonce = randomNonce()
  return serialize({type = "LOCATE_REQUEST", nonce = nonce, clientPublic = myPublicKey}), nonce
end

-- Given a decrypted request string and this host's fixed position, returns
-- the serialized response and the embedded client public key, or nil, err.
local function handleRequestOnHost(message, hostPosition)
  local request = deserialize(message)
  if not (type(request) == "table" and request.type == "LOCATE_REQUEST" and
          request.nonce and request.clientPublic) then
    return nil, nil, "malformed_request"
  end
  local response = serialize({
    type = "LOCATE_RESPONSE",
    nonce = request.nonce,
    x = hostPosition.x,
    y = hostPosition.y,
    z = hostPosition.z
  })
  return response, request.clientPublic, nil
end

-- Given a decrypted response string and the nonce we expect it to echo,
-- returns the response table, or nil, err.
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
  parseResponse = parseResponse,
  buildIdentifyRequest = buildIdentifyRequest,
  handleIdentifyRequestOnHost = handleIdentifyRequestOnHost,
  parseIdentifyResponse = parseIdentifyResponse
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
  while true do
    local senderId, payload = rawReceive()
    if senderId and type(payload) == "string" then
      local reply = handleIdentifyRequestOnHost(payload, myPublicKey)
      if reply then transmit(senderId, reply) end
    elseif senderId and type(payload) == "table" then
      local ok, message = pcall(enc.decrypt, myPrivateKey, payload)
      if ok then
        local response, clientPublic, err = handleRequestOnHost(message, state.hostPosition)
        if response then
          local responsePackage = enc.encrypt(clientPublic, response)
          transmit(senderId, responsePackage)
        end
      end
    end
  end
end

-- ===========================================================================
-- Client side
-- ===========================================================================

-- Sends one request to hostId and blocks up to timeout seconds for a
-- matching, freshly-nonced reply. Returns the measured {x,y,z,d}, or nil, err.
local function pingHost(hostId, hostPublicKey, timeout)
  local payload, nonce = buildRequest(sip.getPublicKey())
  transmit(hostId, enc.encrypt(hostPublicKey, payload))

  local deadline = os.clock() + timeout
  while true do
    local remaining = deadline - os.clock()
    if remaining <= 0 then return nil, "timeout" end
    local senderId, package, distance = rawReceive(remaining)
    if senderId == hostId and type(package) == "table" and type(distance) == "number" then
      local ok, message = pcall(enc.decrypt, sip.getPrivateKey(), package)
      if ok then
        local response, err = parseResponse(message, nonce)
        if response then
          return {x = response.x, y = response.y, z = response.z, d = distance, hostId = senderId}
        end
        -- wrong/stale nonce from this host: keep waiting for the real reply
      end
    end
  end
end

-- Returns x, y, z, nil on a successful fix, or nil, nil, nil, err (e.g.
-- "insufficient_fixes" if jamming/interference prevented quorum).
function sgps.locate(opts)
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

  local function answerCount()
    local n = 0
    for _ in pairs(answers) do n = n + 1 end
    return n
  end

  for attempt = 1, retries do
    if not accumulate then answers = {} end

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
            local point = pingHost(id, hostPublicKey, timeout)
            if point then answers[id] = point end
          end
        end
      end
      parallel.waitForAll(table.unpack(thunks))
    end

    if answerCount() >= minFixes then
      local points = {}
      for _, point in pairs(answers) do points[#points + 1] = point end
      local x, y, z, err = sgps.solveWithOutlierRejection(points, minFixes)
      if x then return x, y, z, nil end
    end

    if attempt < retries then sleep(0.5 * attempt) end
  end

  -- Say how close it got: "2 of 5 answered" points at radio range or dead
  -- hosts, while "5 of 5 answered" points at bad host geometry instead.
  return nil, nil, nil, string.format("insufficient_fixes (%d of %d hosts answered, need %d)",
    answerCount(), #hostIds, minFixes)
end

-- ===========================================================================
-- Diagnostics
-- ===========================================================================

-- Pings every trusted host individually and reports what each one did, so a
-- failing fix can be attributed rather than guessed at. Returns a list of
-- {hostId, ok, distance, latency, x, y, z, err} sorted by host ID.
function sgps.diagnose(opts)
  opts = opts or {}
  local timeout = opts.timeout or sgps.DEFAULT_TIMEOUT
  local hostIds = opts.hostIds or sgps.listTrustedHosts()

  local results = {}
  local thunks = {}
  for _, id in ipairs(hostIds) do
    thunks[#thunks + 1] = function()
      local hostPublicKey = state.trustedHosts[id]
      if not hostPublicKey then
        results[#results + 1] = {hostId = id, ok = false, err = "no pinned key"}
        return
      end
      local started = os.clock()
      local point, err = pingHost(id, hostPublicKey, timeout)
      local latency = os.clock() - started
      if point then
        results[#results + 1] = {hostId = id, ok = true, distance = point.d,
          latency = latency, x = point.x, y = point.y, z = point.z}
      else
        results[#results + 1] = {hostId = id, ok = false, latency = latency,
          err = err or "no reply"}
      end
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
    {x = 0, y = 0, z = 200}, {x = 150, y = 150, z = 150}
  }
  local points = {}
  for i, h in ipairs(hostPositions) do
    local d = math.sqrt((truth.x - h.x) ^ 2 + (truth.y - h.y) ^ 2 + (truth.z - h.z) ^ 2)
    points[i] = {x = h.x, y = h.y, z = h.z, d = d}
  end

  local x, y, z, err = trilaterate({points[1], points[2], points[3], points[4]})
  check("exact trilateration",
    x and math.abs(x - truth.x) < 0.01 and math.abs(y - truth.y) < 0.01 and math.abs(z - truth.z) < 0.01)

  local withOutlier = {}
  for i = 1, #points do
    withOutlier[i] = {x = points[i].x, y = points[i].y, z = points[i].z, d = points[i].d}
  end
  withOutlier[5].d = withOutlier[5].d + 500
  local x2, y2, z2, err2 = sgps.solveWithOutlierRejection(withOutlier, 4)
  check("outlier rejection",
    x2 and math.abs(x2 - truth.x) < 0.01 and math.abs(y2 - truth.y) < 0.01 and math.abs(z2 - truth.z) < 0.01)

  local x3, _, _, err3 = trilaterate({points[1], points[2], points[3]})
  check("insufficient points rejected", x3 == nil and err3 == "insufficient_points")

  local fakePublicKey = {n = "abcd", e = "10001"}
  local request, nonce = buildRequest(fakePublicKey)
  local response, clientPublic, reqErr = handleRequestOnHost(request, {x = 12, y = 34, z = -56})
  local parsed, parseErr = parseResponse(response, nonce)
  check("request/response round trip",
    reqErr == nil and clientPublic.n == "abcd" and
    parsed and parsed.x == 12 and parsed.y == 34 and parsed.z == -56)

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

  print(allPassed and "SELF TEST PASSED" or "SELF TEST FAILED")
  return allPassed
end

local progArgs = {...}
if progArgs[1] == "test" then
  sgps.selfTest()
end

return sgps
