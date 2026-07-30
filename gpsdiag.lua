--[[
  gpsdiag.lua - works out why fixes are failing, and says which of the causes
  it actually is.

  Run it on the computer that's having trouble:

    gpsdiag

  It tests each host two independent ways:

    PROBE  - a plaintext "who are you" exchange. No encryption, no pinned key.
             This asks only: is that computer there, running, and in radio
             range, and does the reply carry a block distance?
    PING   - the full encrypted position request, exactly as a real fix does.

  Splitting those apart is the point, because several very different problems
  all look like "no fix" from the outside:

    probe fails everywhere      -> radio range, hosts not running, or their
                                   chunks are unloaded. If ALL hosts fail at
                                   once they're probably clustered together or
                                   loaded/unloaded together, rather than each
                                   being individually marginal.
    probe works, no distance    -> this computer is using a WIRED modem. Wired
                                   modems report no distance, and sGps needs it,
                                   so every reply gets discarded. Use wireless.
    probe works, ping fails     -> the host regenerated its keypair, so the key
                                   pinned here no longer matches. Re-pin.
    all pings work, fix fails   -> host geometry, usually all at one altitude.
]]

local CONFIG = {
  modemSide = nil,
  passphrase = "change-this-passphrase",
  hostsPath = "/trusted_hosts.tbl",
  rounds = 3
}

local sip = dofile("/sip.lua")
local sgps = dofile("/sgps/sGps.lua")
sgps.useSip(sip)

local IDENTITIES = {
  {"/ship_public.key",  "/ship_private.key"},
  {"/host_public.key",  "/host_private.key"},
  {"/pilot_public.key", "/pilot_private.key"},
  {"/watch_public.key", "/watch_private.key"}
}

local loaded = false
for _, pair in ipairs(IDENTITIES) do
  if fs.exists(pair[1]) and fs.exists(pair[2]) then
    if pcall(sip.loadIdentity, pair[1], pair[2], CONFIG.passphrase) then
      loaded = true
      break
    end
  end
end
if not loaded then
  print("No existing identity found; generating a temporary one...")
  sip.generateIdentity(256)
end

sgps.open(CONFIG.modemSide)

-- ---- radio ----------------------------------------------------------------

local modem = sgps.modemInfo()
print("Modem: side " .. tostring(modem and modem.side))
if modem and modem.known and not modem.wireless then
  print("")
  print("  *** This is a WIRED modem. ***")
  print("  Wired modems report no distance, and sGps needs the block distance")
  print("  to work at all - every reply will be discarded, so you will get")
  print("  zero fixes no matter how healthy everything else looks.")
  print("  Attach a WIRELESS (or ender) modem instead.")
  print("")
elseif modem and modem.wireless then
  print("  wireless: yes")
end

if fs.exists(CONFIG.hostsPath) then sgps.loadTrustedHosts(CONFIG.hostsPath) end
local hostIds = sgps.listTrustedHosts()

if #hostIds == 0 then
  error("gpsdiag.lua: no hosts pinned here. Run install.lua or watch.lua first.", 0)
end

print("Pinned hosts: " .. #hostIds .. "   (need " .. sgps.DEFAULT_MIN_FIXES ..
  " answering at once)")
print("")

-- ---- sweep ----------------------------------------------------------------

local stats = {}
for _, id in ipairs(hostIds) do
  stats[id] = {reachable = 0, pinged = 0, noDistance = 0, keyChanged = 0}
end
local lastResults = nil

for round = 1, CONFIG.rounds do
  print("Round " .. round .. "/" .. CONFIG.rounds .. ":")
  local results = sgps.diagnose()
  lastResults = results

  for _, r in ipairs(results) do
    local s = stats[r.hostId]
    if r.reachable then s.reachable = s.reachable + 1 end
    if r.ok then s.pinged = s.pinged + 1 end
    if r.distanceMissing then s.noDistance = s.noDistance + 1 end
    if r.keyChanged then s.keyChanged = s.keyChanged + 1 end

    if r.ok then
      print(string.format("  %-4d ok       %6.1f blocks  %.2fs  at %d,%d,%d",
        r.hostId, r.distance, r.latency or 0, r.x, r.y, r.z))
    elseif r.keyChanged then
      print(string.format("  %-4d KEY CHANGED - host answered but with a different key",
        r.hostId))
    elseif r.distanceMissing then
      print(string.format("  %-4d no distance in reply (wired modem?)", r.hostId))
    elseif r.reachable then
      print(string.format("  %-4d reachable, but position request failed: %s",
        r.hostId, tostring(r.err)))
    else
      print(string.format("  %-4d unreachable (no answer to plaintext probe)", r.hostId))
    end
  end
  print("")
  if round < CONFIG.rounds then sleep(1) end
end

-- ---- summary --------------------------------------------------------------

local reachableAlways, reachableSometimes, reachableNever = 0, 0, 0
local pingAlways, anyNoDistance, anyKeyChanged = 0, 0, 0

print("Over " .. CONFIG.rounds .. " rounds:")
for _, id in ipairs(hostIds) do
  local s = stats[id]
  local label
  if s.reachable == CONFIG.rounds then label = "always reachable"; reachableAlways = reachableAlways + 1
  elseif s.reachable == 0 then label = "NEVER reachable"; reachableNever = reachableNever + 1
  else label = "INTERMITTENT"; reachableSometimes = reachableSometimes + 1 end

  if s.pinged == CONFIG.rounds then pingAlways = pingAlways + 1 end
  if s.noDistance > 0 then anyNoDistance = anyNoDistance + 1 end
  if s.keyChanged > 0 then anyKeyChanged = anyKeyChanged + 1 end

  print(string.format("  host %-4d probe %d/%d, ping %d/%d  %s",
    id, s.reachable, CONFIG.rounds, s.pinged, CONFIG.rounds, label))
end
print("")

if lastResults then
  local ok, reason = sgps.checkGeometry(lastResults)
  print("Geometry: " .. (ok and "ok" or "PROBLEM"))
  print("  " .. reason)
  print("")
end

print("Attempting a real fix...")
local x, y, z, err = sgps.locate()
if x then
  print(string.format("  OK: %.1f, %.1f, %.1f", x, y, z))
else
  print("  failed: " .. tostring(err))
end
print("")

-- ---- verdict --------------------------------------------------------------

print("Diagnosis:")

if anyNoDistance > 0 then
  print("  Replies are arriving WITHOUT a block distance. That means a wired")
  print("  modem somewhere in the path. sGps cannot work without the distance")
  print("  a wireless modem_message carries. Swap to a wireless/ender modem")
  print("  on this computer and on the hosts.")
elseif anyKeyChanged > 0 then
  print("  " .. anyKeyChanged .. " host(s) answered with a DIFFERENT key than the one")
  print("  pinned here - they regenerated their keypair (their key files were")
  print("  deleted, or the passphrase changed so gpshost.lua made new ones).")
  print("  Nothing they send can be decrypted. Delete " .. CONFIG.hostsPath)
  print("  on this computer and re-run watch.lua to pin the new keys.")
elseif reachableNever == #hostIds then
  print("  NO host answered even a plaintext probe, in any round. The problem is")
  print("  before any encryption:")
  print("    - are the host computers actually running gpshost.lua?")
  print("    - are their chunks loaded? A computer in an unloaded chunk stops")
  print("      dead, and if all your hosts are in one area they all stop")
  print("      together - which looks exactly like this.")
  print("    - is this computer in wireless range? Range depends on altitude;")
  print("      clustered hosts go in and out of range all at once.")
elseif reachableAlways >= sgps.DEFAULT_MIN_FIXES and pingAlways >= sgps.DEFAULT_MIN_FIXES then
  print("  Radio and keys are healthy. If fixes still fail it is geometry -")
  print("  see the Geometry line above.")
elseif reachableAlways + reachableSometimes >= sgps.DEFAULT_MIN_FIXES then
  print("  Enough hosts exist, but " .. reachableSometimes .. " answer only sometimes.")
  print("  That is what makes fixes intermittent. Check their distances above:")
  print("  marginal links drop in and out. Raise the hosts, move them closer,")
  print("  or use ender modems.")
else
  print("  Only " .. (reachableAlways + reachableSometimes) .. " host(s) reachable; " ..
    sgps.DEFAULT_MIN_FIXES .. " needed.")
  print("  Check the hosts are running, chunk-loaded, and within radio range.")
end
