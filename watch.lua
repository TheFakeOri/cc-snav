--[[
  watch.lua - prints the current position every time it changes, and nothing
  when it doesn't. Useful for checking the GPS constellation actually works,
  for reading coordinates off a moving ship, and for finding out how much your
  fixes jitter when parked.

  Run it anywhere with a wireless modem that can reach your sGps hosts:

    watch

  It reuses whatever this computer already has - existing keys rather than
  generating new ones, and already-pinned hosts rather than re-pinning. On a
  computer set up by install.lua it needs no configuration at all.

  Ctrl+T to stop.

  Note the MIN_CHANGE threshold below. A stationary computer's fixes wobble in
  the low decimals (least-squares on exact distances is stable, but not
  bit-identical), so reporting every numerical difference would scroll forever
  while sitting still. Only movement past the threshold counts as a change.
]]

local CONFIG = {
  -- Only needed if this computer has never pinned any hosts. If
  -- /trusted_hosts.tbl or /heli_config.tbl exists, it's read from there.
  gpsHostIds = {},

  modemSide = nil,
  keyBits = 256,
  hostsPath = "/trusted_hosts.tbl",
  passphrase = "change-this-passphrase",

  minChange = 0.5,   -- blocks of movement before it counts as a change
  interval = 0.5,    -- seconds to wait between fix attempts
  showY = true       -- set false if altitude noise is distracting
}

if fs.exists("/watch_config.tbl") then
  local f = fs.open("/watch_config.tbl", "r")
  local ok, saved = pcall(textutils.unserialize, f.readAll())
  f.close()
  if ok and type(saved) == "table" then
    for key, value in pairs(saved) do CONFIG[key] = value end
  end
end

local sip = dofile("/sip.lua")
local sgps = dofile("/sgps/sGps.lua")
sgps.useSip(sip)

-- ---- identity -------------------------------------------------------------
-- Reuse an existing keypair if this computer has one. Not for speed - keygen
-- is cheap now - but for identity continuity: a computer that invents a new
-- key every run looks like a different peer to everything that pinned it.

local IDENTITIES = {
  {"/ship_public.key",  "/ship_private.key"},
  {"/host_public.key",  "/host_private.key"},
  {"/pilot_public.key", "/pilot_private.key"},
  {"/watch_public.key", "/watch_private.key"}
}

local loaded = false
for _, pair in ipairs(IDENTITIES) do
  if fs.exists(pair[1]) and fs.exists(pair[2]) then
    local ok = pcall(sip.loadIdentity, pair[1], pair[2], CONFIG.passphrase)
    if ok then
      print("Using existing identity: " .. pair[2])
      loaded = true
      break
    end
  end
end

if not loaded then
  print("Generating a " .. CONFIG.keyBits .. "-bit keypair...")
  sip.generateIdentity(CONFIG.keyBits)
  sip.saveIdentity("/watch_public.key", "/watch_private.key", CONFIG.passphrase)
end

-- ---- radio and hosts ------------------------------------------------------

sgps.open(CONFIG.modemSide)

if fs.exists(CONFIG.hostsPath) then
  sgps.loadTrustedHosts(CONFIG.hostsPath)
end

if #sgps.listTrustedHosts() == 0 then
  -- Fall back to the ship's host list, then to this file's own config.
  local hostIds = CONFIG.gpsHostIds
  if #hostIds == 0 and fs.exists("/heli_config.tbl") then
    local f = fs.open("/heli_config.tbl", "r")
    local ok, saved = pcall(textutils.unserialize, f.readAll())
    f.close()
    if ok and type(saved) == "table" and type(saved.gpsHostIds) == "table" then
      hostIds = saved.gpsHostIds
    end
  end

  if #hostIds == 0 then
    error("watch.lua: no GPS hosts known. Either run install.lua on this " ..
      "computer, or fill in CONFIG.gpsHostIds here.", 0)
  end

  print("Pinning " .. #hostIds .. " GPS hosts...")
  for _, id in ipairs(hostIds) do
    local key, err = sgps.trustHostById(id, 5)
    print("  host " .. id .. "  " ..
      (key and sgps.publicKeyFingerprint(key) or ("unreachable (" .. tostring(err) .. ")")))
  end
  if #sgps.listTrustedHosts() > 0 then
    sgps.saveTrustedHosts(CONFIG.hostsPath)
  end
end

local hostCount = #sgps.listTrustedHosts()
print("Watching position using " .. hostCount .. " pinned host(s). Ctrl+T to stop.")
if hostCount < 4 then
  print("WARNING: sGps needs 4 hosts for a fix by default - expect failures.")
end
print("")

-- ---- watch ----------------------------------------------------------------

local function stamp()
  return textutils.formatTime(os.time(), true)
end

local last = nil
local lastFailed = false
local fixes, changes = 0, 0

while true do
  local x, y, z, err = sgps.locate()

  if x then
    fixes = fixes + 1
    lastFailed = false

    local moved = nil
    if last then
      local dx, dy, dz = x - last.x, y - last.y, z - last.z
      moved = math.sqrt(dx * dx + dy * dy + dz * dz)
    end

    if not last or moved >= CONFIG.minChange then
      changes = changes + 1
      if CONFIG.showY then
        write(string.format("[%s] %.1f, %.1f, %.1f", stamp(), x, y, z))
      else
        write(string.format("[%s] %.1f, %.1f", stamp(), x, z))
      end
      if moved then
        write(string.format("   (moved %.1f)", moved))
      else
        write("   (first fix)")
      end
      print("")
      last = {x = x, y = y, z = z}
    end
  else
    -- Only report a failure when it starts, so a jammed or out-of-range
    -- computer doesn't scroll the same line forever.
    if not lastFailed then
      print(string.format("[%s] no fix: %s", stamp(), tostring(err)))
      lastFailed = true
    end
  end

  sleep(CONFIG.interval)
end
