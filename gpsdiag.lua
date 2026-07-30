--[[
  gpsdiag.lua - works out why fixes are failing.

  Run it on the computer that's having trouble:

    gpsdiag

  It pings each pinned host individually and shows which answered, how far away
  each one is, and how long it took - then checks whether the hosts that
  answered are actually arranged well enough to solve a position from, and
  tries a real fix.

  What the results mean:

    Fewer hosts answered than you have
      Radio range, or a host that isn't running. Wireless modem range in
      CC:Tweaked depends on altitude - low computers reach far less than high
      ones, and range shrinks in bad weather. The distance column tells you
      which links are marginal: anything near the range limit will come and go,
      which is exactly what makes fixes work "sometimes". Raise the hosts, move
      them closer, or use Ender modems.

    All hosts answered but the fix still fails
      Geometry. Hosts all at one altitude cannot pin down height. Move one well
      above or below the others.

    Slow latencies (over a second or two)
      Normal - each ping is several RSA operations. Only a problem if it exceeds
      sgps.DEFAULT_TIMEOUT.
]]

local CONFIG = {
  modemSide = nil,
  passphrase = "change-this-passphrase",
  hostsPath = "/trusted_hosts.tbl",
  rounds = 3          -- repeat the sweep, to catch links that flicker
}

local sip = dofile("/sip.lua")
local sgps = dofile("/sgps/sGps.lua")
sgps.useSip(sip)

-- Reuse whatever identity this computer already has rather than burning a
-- minute on keygen just to run a diagnostic.
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

if fs.exists(CONFIG.hostsPath) then sgps.loadTrustedHosts(CONFIG.hostsPath) end
local hostIds = sgps.listTrustedHosts()

if #hostIds == 0 then
  error("gpsdiag.lua: no hosts pinned on this computer. Run install.lua or " ..
    "watch.lua first so they get pinned.", 0)
end

print("Pinned hosts: " .. #hostIds .. "   (sGps needs " ..
  sgps.DEFAULT_MIN_FIXES .. " answering at once)")
print("")

-- Tracks how reliable each host is across rounds; a host that answers 2 of 3
-- times is the real culprit behind intermittent fixes.
local answered, lastResults = {}, nil
for _, id in ipairs(hostIds) do answered[id] = 0 end

for round = 1, CONFIG.rounds do
  print("Round " .. round .. " of " .. CONFIG.rounds .. ":")
  local results = sgps.diagnose()
  lastResults = results

  for _, r in ipairs(results) do
    if r.ok then
      answered[r.hostId] = answered[r.hostId] + 1
      print(string.format("  host %-4d OK    %6.1f blocks away   %.2fs   at %d,%d,%d",
        r.hostId, r.distance, r.latency, r.x, r.y, r.z))
    else
      print(string.format("  host %-4d ----  %s (%.2fs)",
        r.hostId, tostring(r.err), r.latency or 0))
    end
  end
  print("")
  if round < CONFIG.rounds then sleep(1) end
end

-- ---- summary --------------------------------------------------------------

print("Reliability over " .. CONFIG.rounds .. " rounds:")
local always, sometimes, never = 0, 0, 0
for _, id in ipairs(hostIds) do
  local n = answered[id]
  local verdict
  if n == CONFIG.rounds then verdict = "always"; always = always + 1
  elseif n == 0 then verdict = "NEVER"; never = never + 1
  else verdict = "INTERMITTENT"; sometimes = sometimes + 1 end
  print(string.format("  host %-4d %d/%d  %s", id, n, CONFIG.rounds, verdict))
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
  print(string.format("  fix OK: %.1f, %.1f, %.1f", x, y, z))
else
  print("  failed: " .. tostring(err))
end
print("")

-- ---- verdict --------------------------------------------------------------

print("Diagnosis:")
if always >= sgps.DEFAULT_MIN_FIXES then
  print("  Enough hosts answer reliably. If fixes still fail, it's geometry -")
  print("  check the line above.")
elseif always + sometimes >= sgps.DEFAULT_MIN_FIXES then
  print("  You have enough hosts in principle, but " .. sometimes .. " answer only")
  print("  sometimes - that is what makes fixes intermittent. Look at their")
  print("  distances above: marginal radio links drop in and out. Raise those")
  print("  hosts higher, move them closer, or switch to Ender modems.")
else
  print("  Only " .. (always + sometimes) .. " host(s) are reachable at all, and " ..
    sgps.DEFAULT_MIN_FIXES .. " are needed.")
  if never > 0 then
    print("  " .. never .. " host(s) never answered - check they are running")
    print("  gpshost.lua, have a wireless modem, and are in range.")
  end
end
