--[[
  pilot.lua - operator console. Run this on a ground computer to command the
  helicopter.

  Copy to the operator computer along with enc.lua, sip.lua, sgps/sGps.lua and
  nav/sNav.lua, set CONFIG.shipId, and run it. This computer's ID must be in
  the ship's CONFIG.operatorIds or every command comes back refused.

  Commands:
    goto <x> <y> <z>   fly there
    status             position, heading, speed, tail deflection, mission
    stop               abandon the current mission and hold
    quit
]]

local CONFIG = {
  shipId = nil,        -- REQUIRED: the helicopter's computer ID
  modemSide = nil,     -- nil = autodetect
  keyBits = 256,
  publicKeyPath  = "/pilot_public.key",
  privateKeyPath = "/pilot_private.key",
  passphrase     = "change-this-passphrase"
}

-- install.lua writes this file, so the console can be configured without
-- editing Lua. Anything in it overrides the defaults above.
if fs.exists("/pilot_config.tbl") then
  local f = fs.open("/pilot_config.tbl", "r")
  local ok, saved = pcall(textutils.unserialize, f.readAll())
  f.close()
  if ok and type(saved) == "table" then
    for key, value in pairs(saved) do CONFIG[key] = value end
  end
end

assert(CONFIG.shipId,
  "pilot.lua: no ship ID set. Run install.lua, or fill in CONFIG.shipId here.")

local nav = dofile("/nav/sNav.lua")
local sip = nav.sip

if fs.exists(CONFIG.privateKeyPath) and fs.exists(CONFIG.publicKeyPath) then
  sip.loadIdentity(CONFIG.publicKeyPath, CONFIG.privateKeyPath, CONFIG.passphrase)
else
  print("Generating a " .. CONFIG.keyBits .. "-bit keypair...")
  sip.generateIdentity(CONFIG.keyBits)
  sip.saveIdentity(CONFIG.publicKeyPath, CONFIG.privateKeyPath, CONFIG.passphrase)
end

-- sip.open(nil) autodetects, and prefers a wireless modem over a wired one -
-- which an open-coded "first modem on any side" search here did not.
sip.open(CONFIG.modemSide)

print("Pilot console. This computer is ID " .. os.getComputerID() ..
  " - it must be authorised on the ship.")
print("Commanding ship " .. CONFIG.shipId .. ". Type 'quit' to exit.")

local function send(command)
  local reply, err = nav.sendCommand(CONFIG.shipId, command, 15)
  if not reply then
    print("  no reply: " .. tostring(err))
    return nil
  end
  if not reply.ok then
    print("  refused: " .. tostring(reply.err))
    return nil
  end
  return reply
end

local function showStatus(reply)
  local s, m = reply.state, reply.model
  if s.pos then
    print(string.format("  at %.1f, %.1f, %.1f", s.pos.x, s.pos.y, s.pos.z))
  else
    print("  no position fix yet")
  end
  print(string.format("  heading %.0f%s  speed %.1f b/s  tail %+d steps",
    s.heading, s.headingKnown and "" or " (stale)", s.speed, s.yawDeflection or 0))
  print(string.format("  fixes %d  fix age %s  mission %s",
    s.fixCount,
    s.fixAge and string.format("%.1fs", s.fixAge) or "never",
    s.mission and string.format("%d, %d, %d", s.mission.x, s.mission.y, s.mission.z) or "idle"))
  if s.lastError then print("  last error: " .. tostring(s.lastError)) end
  if reply.capabilities then
    print("  yaw mode: " .. tostring(reply.capabilities.yawMode) ..
      "   reverse: " .. tostring(reply.capabilities.reverse) ..
      "   vertical: " .. tostring(reply.capabilities.vertical))
  end
end

while true do
  write("> ")
  local line = read()
  if not line then break end
  local parts = {}
  for word in line:gmatch("%S+") do parts[#parts + 1] = word end
  local cmd = (parts[1] or ""):lower()

  if cmd == "quit" or cmd == "exit" then
    break
  elseif cmd == "goto" then
    local x, y, z = tonumber(parts[2]), tonumber(parts[3]), tonumber(parts[4])
    if not (x and y and z) then
      print("  usage: goto <x> <y> <z>")
    else
      local reply = send({cmd = "GOTO", x = x, y = y, z = z})
      if reply then print(string.format("  accepted: flying to %d, %d, %d", x, y, z)) end
    end
  elseif cmd == "stop" then
    if send({cmd = "STOP"}) then print("  stopping") end
  elseif cmd == "status" then
    local reply = send({cmd = "STATUS"})
    if reply then showStatus(reply) end
  elseif cmd ~= "" then
    print("  commands: goto <x> <y> <z> | status | stop | quit")
  end
end

print("Console closed. The ship keeps running whatever mission it has.")
