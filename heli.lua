--[[
  heli.lua - run this on the computer riding the helicopter.

  Copy to the ship's computer as `startup.lua`, along with enc.lua, sip.lua,
  sgps/sGps.lua and nav/sNav.lua. Fill in CONFIG.gpsHostIds and
  CONFIG.operatorIds, then reboot.

  What it does, in order: loads or generates this ship's keypair, pins the GPS
  hosts, sets up the stepped tail actuator, loads (or measures) the flight
  model, then waits for GOTO commands from an authorised operator.

  BEFORE FIRST BOOT: centre the tail by hand. There is no position feedback
  from a Sequenced Gearshift, so the software believes the tail is centred
  when it starts. If it isn't, every steering decision inherits that error.
]]

local CONFIG = {
  -- REQUIRED: the computer IDs of your sGps hosts, as printed by gpshost.lua.
  -- Needs at least nav-level minFixes of them (4 by default).
  gpsHostIds = {},

  -- REQUIRED: computer IDs allowed to command this ship. Anything else gets
  -- an explicit refusal.
  operatorIds = {},

  modemSide = nil,     -- nil = autodetect
  keyBits = 256,

  publicKeyPath  = "/ship_public.key",
  privateKeyPath = "/ship_private.key",
  hostsPath      = "/trusted_hosts.tbl",
  modelPath      = "/heli.model",
  passphrase     = "change-this-passphrase",

  -- Set false if your tail steers the wrong way; swaps which redstone side
  -- carries the step pulse and which carries direction.
  swapYawSides = false
}

-- install.lua writes this file, so the ship can be configured without editing
-- Lua. Anything in it overrides the defaults above.
if fs.exists("/heli_config.tbl") then
  local f = fs.open("/heli_config.tbl", "r")
  local ok, saved = pcall(textutils.unserialize, f.readAll())
  f.close()
  if ok and type(saved) == "table" then
    for key, value in pairs(saved) do CONFIG[key] = value end
  end
end

assert(#CONFIG.gpsHostIds > 0,
  "heli.lua: no GPS hosts set. Run install.lua, or fill in CONFIG.gpsHostIds here.")
assert(#CONFIG.operatorIds > 0,
  "heli.lua: no operators set. Run install.lua, or fill in CONFIG.operatorIds here.")

local nav = dofile("/nav/sNav.lua")
local sip, sgps = nav.sip, nav.sgps

-- ---- identity -------------------------------------------------------------

if fs.exists(CONFIG.privateKeyPath) and fs.exists(CONFIG.publicKeyPath) then
  sip.loadIdentity(CONFIG.publicKeyPath, CONFIG.privateKeyPath, CONFIG.passphrase)
else
  print("Generating a " .. CONFIG.keyBits .. "-bit keypair; this takes a minute...")
  sip.generateIdentity(CONFIG.keyBits)
  sip.saveIdentity(CONFIG.publicKeyPath, CONFIG.privateKeyPath, CONFIG.passphrase)
end

print("Ship computer ID: " .. os.getComputerID())
print("Ship fingerprint: " .. sgps.publicKeyFingerprint(sip.getPublicKey()))

-- ---- radios ---------------------------------------------------------------
-- sGps needs the raw modem (rednet discards the block-distance it depends on);
-- sip rides rednet for the command channel. Same modem, both opened.

sgps.open(CONFIG.modemSide)
sip.open(CONFIG.modemSide or (function()
  for _, side in ipairs(peripheral.getNames()) do
    if peripheral.getType(side) == "modem" then return side end
  end
end)())

-- ---- GPS hosts ------------------------------------------------------------
-- Pinned once and reused. Re-pinning every boot would mean trusting whatever
-- answers each time; pinning once means a substituted host stops matching.

if fs.exists(CONFIG.hostsPath) then
  sgps.loadTrustedHosts(CONFIG.hostsPath)
  print("Loaded " .. #sgps.listTrustedHosts() .. " pinned GPS hosts.")
else
  print("Pinning GPS hosts (first run)...")
  local pinned = 0
  for _, id in ipairs(CONFIG.gpsHostIds) do
    local key, err = sgps.trustHostById(id, 5)
    if key then
      pinned = pinned + 1
      print("  host " .. id .. "  " .. sgps.publicKeyFingerprint(key))
    else
      print("  host " .. id .. "  UNREACHABLE (" .. tostring(err) .. ")")
    end
  end
  print("Check those fingerprints against what each host printed.")
  if pinned > 0 then
    sgps.saveTrustedHosts(CONFIG.hostsPath)
  else
    print("No hosts answered - not saving. Fix the radios and reboot.")
  end
end

-- ---- controls -------------------------------------------------------------

local controlMap = {
  forward      = {side = "front"},
  reverse      = {side = "back"},
  yawStep      = {side = CONFIG.swapYawSides and "right" or "left"},
  yawDirection = {side = CONFIG.swapYawSides and "left" or "right"},
  up           = {side = "top"},
  down         = {side = "bottom"}
}
nav.setControlMap(controlMap)
nav.assumeYawCentered() -- trusts that you centred the tail by hand

for _, id in ipairs(CONFIG.operatorIds) do nav.authorizeOperator(id) end

-- ---- flight model ---------------------------------------------------------

if nav.loadModel(CONFIG.modelPath) then
  local m = nav.getModel()
  print(string.format("Flight model: %.1f b/s top, %.1f b/s^2 coast, %.0f deg/s yaw",
    m.maxSpeed, m.coastDecel, m.yawRate))
else
  print("")
  print("No flight model found. Calibration will fly this ship at FULL")
  print("THROTTLE in a straight line and then in a turn.")
  print("Make sure it is high up and in open air.")
  print("Type 'yes' to calibrate now, anything else to fly on defaults:")
  if read() == "yes" then
    local model, err = nav.calibrate()
    if model then
      nav.saveModel(CONFIG.modelPath)
      print("Calibrated and saved.")
    else
      print("Calibration failed: " .. tostring(err) .. " - flying on defaults.")
    end
  else
    print("Using default model. Expect sloppy braking until you calibrate.")
  end
end

-- ---- fly ------------------------------------------------------------------

print("")
print("Awaiting commands from operators: " .. table.concat(CONFIG.operatorIds, ", "))

nav.serveRemote({
  onMissionEnd = function(ok, err, target)
    if ok then
      print(string.format("Arrived at %d, %d, %d", target.x, target.y, target.z))
    else
      print("Mission ended: " .. tostring(err))
    end
  end
})
