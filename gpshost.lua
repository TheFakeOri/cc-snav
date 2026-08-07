--[[
  gpshost.lua - run this on each sGps host computer.

  You need at least four of these, at surveyed positions, spread out in all
  three axes. Four hosts sitting in a flat line or a flat square give the
  trilateration solver nothing to work with vertically and it will either
  refuse to solve or return nonsense - put at least one of them well above
  or below the others.

  Copy this to a host computer as `startup.lua` (along with enc.lua, sip.lua
  and sgps/sGps.lua), fill in CONFIG.position from F3, and reboot.

  On first run it generates an RSA keypair, then prints its fingerprint. That
  keypair is saved, so later boots start immediately.
]]

local CONFIG = {
  -- REQUIRED: this computer's exact block position, read off F3. The whole
  -- system's accuracy rests on these numbers being right.
  position = {x = nil, y = nil, z = nil},

  modemSide = nil,       -- nil = autodetect the attached wireless modem
  keyBits = 256,

  publicKeyPath  = "/host_public.key",
  privateKeyPath = "/host_private.key",

  -- Encrypts the private key at rest. Stored in this file, so it stops
  -- someone reading the key out with `edit`, not someone who can run code on
  -- this computer. See the storage notes in enc.lua.
  passphrase = "change-this-passphrase"
}

-- install.lua writes this file, so a host can be configured without editing
-- Lua. Anything in it overrides the defaults above.
if fs.exists("/host_config.tbl") then
  local f = fs.open("/host_config.tbl", "r")
  local ok, saved = pcall(textutils.unserialize, f.readAll())
  f.close()
  if ok and type(saved) == "table" then
    for key, value in pairs(saved) do CONFIG[key] = value end
  end
end

assert(CONFIG.position.x and CONFIG.position.y and CONFIG.position.z,
  "gpshost.lua: no position set. Run install.lua, or fill in CONFIG.position here.")

local sip = dofile("/sip.lua")
local sgps = dofile("/sgps/sGps.lua")
sgps.useSip(sip) -- one shared identity across both layers

if fs.exists(CONFIG.privateKeyPath) and fs.exists(CONFIG.publicKeyPath) then
  sip.loadIdentity(CONFIG.publicKeyPath, CONFIG.privateKeyPath, CONFIG.passphrase)
else
  print("Generating a " .. CONFIG.keyBits .. "-bit keypair...")
  sip.generateIdentity(CONFIG.keyBits)
  sip.saveIdentity(CONFIG.publicKeyPath, CONFIG.privateKeyPath, CONFIG.passphrase)
  print("Keypair saved.")
end

sgps.open(CONFIG.modemSide)
sgps.host(CONFIG.position.x, CONFIG.position.y, CONFIG.position.z)

-- Write these two lines down. The helicopter needs the ID to trust this host,
-- and the fingerprint is how you confirm it pinned the right key.
print("")
print("sGps host running.")
print("  computer ID : " .. os.getComputerID())
print("  fingerprint : " .. sgps.publicKeyFingerprint(sip.getPublicKey()))
print("  position    : " .. CONFIG.position.x .. ", " .. CONFIG.position.y ..
  ", " .. CONFIG.position.z)
print("")

sgps.hostLoop()
