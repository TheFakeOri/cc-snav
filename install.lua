--[[
  install.lua - one-step installer. Puts the libraries and one role script
  onto a computer, writes its config, and sets it to run on boot.

  THREE WAYS TO USE IT

  0. Over the internet, one short command per computer (see SOURCES below):
       pastebin run <code>
     or, if you'd rather not use pastebin at all:
       wget run https://raw.githubusercontent.com/you/repo/main/install.lua

  1. Install floppy (no internet needed, but the files may not fit a 125 kB
     floppy - sNav.lua alone is ~68 kB):
       Craft a Disk Drive and a Floppy Disk. On a computer that already has
       these files, put the drive next to it and run:
         copy /enc.lua /disk/
         copy /sip.lua /disk/
         copy /sgps /disk/sgps
         copy /nav /disk/nav
         copy /gpshost.lua /disk/
         copy /heli.lua /disk/
         copy /pilot.lua /disk/
         copy /install.lua /disk/
         copy /diskstartup.lua /disk/startup.lua
       Now for every new computer: attach a drive, insert the floppy, reboot.
       It installs itself and asks what the computer is. Take the floppy out
       afterwards.

  NON-INTERACTIVE USE
    install host 128 72 -340     GPS host at those coordinates
    install heli                 the helicopter
    install pilot                an operator console

  Re-running is safe: it overwrites the libraries and leaves saved keys and
  flight models alone.

  ---------------------------------------------------------------------------
  SOURCES - it tries these in order: a local directory (floppy), BASE_URL,
  then PASTEBIN codes. Fill in whichever you're using.

  Easiest reliable setup, one short command per computer:
    1. Put the libraries and role scripts in a GitHub repo (or gist). Set
       BASE_URL to the raw address of the folder holding them.
    2. Upload THIS file to pastebin - run `publish.lua` on a computer that
       has everything, and it does the uploading and prints the codes for you.
    3. On each new computer: pastebin run <code>

  Pure pastebin, no GitHub: leave BASE_URL nil and fill in every PASTEBIN
  entry instead. Works, but pastebin is rate-limited when uploading and its
  API is blocked by Cloudflare often enough to be annoying - if downloads
  start failing with HTML errors, that's why, and GitHub raw won't do that.
  ---------------------------------------------------------------------------
]]

-- Raw address of the directory holding these files. Must end with a slash.
local BASE_URL = "https://raw.githubusercontent.com/TheFakeOri/cc-snav/main/"

-- Per-file pastebin codes, used only for files BASE_URL didn't provide.
local PASTEBIN = {
  -- ["enc.lua"]       = "xxxxxxxx",
  -- ["sip.lua"]       = "xxxxxxxx",
  -- ["sgps/sGps.lua"] = "xxxxxxxx",
  -- ["nav/sNav.lua"]  = "xxxxxxxx",
  -- ["gpshost.lua"]   = "xxxxxxxx",
  -- ["heli.lua"]      = "xxxxxxxx",
  -- ["pilot.lua"]     = "xxxxxxxx",
}

local LIBRARIES = {"enc.lua", "sip.lua", "sgps/sGps.lua", "nav/sNav.lua"}

-- Handy on any machine, regardless of role, and small.
local EXTRAS = {"watch.lua", "gpsdiag.lua"}

local ROLES = {
  host  = {script = "gpshost.lua", label = "sGps position host"},
  heli  = {script = "heli.lua",    label = "helicopter autopilot"},
  pilot = {script = "pilot.lua",   label = "operator console"},
  watch = {script = "watch.lua",   label = "position watcher"}
}

local args = {...}

-- ---------------------------------------------------------------------------
-- Finding the files: whichever directory holds enc.lua wins, otherwise HTTP.
-- ---------------------------------------------------------------------------

local function scriptDir()
  local ok, info = pcall(debug.getinfo, 2, "S")
  if ok and info and info.source then
    local path = info.source:match("^@(.*)$") or info.source
    local dir = path:match("^(.*)[/\\][^/\\]*$")
    if dir then return dir end
  end
  return nil
end

local function findSourceDir()
  local candidates = {}
  local dir = scriptDir()
  if dir then candidates[#candidates + 1] = dir end
  candidates[#candidates + 1] = "/disk"
  for i = 1, 6 do candidates[#candidates + 1] = "/disk" .. i end
  candidates[#candidates + 1] = ""
  for _, base in ipairs(candidates) do
    if fs.exists(fs.combine(base, "enc.lua")) then return base end
  end
  return nil
end

local sourceDir = findSourceDir()

local function httpFetch(url)
  if not http then return nil, "HTTP is disabled on this server" end
  local response, err = http.get(url)
  if not response then return nil, tostring(err or "no response") end
  local body = response.readAll()
  local status = response.getResponseCode and response.getResponseCode() or 200
  response.close()
  if status ~= 200 then return nil, "HTTP " .. tostring(status) end
  return body
end

-- A failed pastebin or GitHub request usually answers with an HTML error page
-- rather than an error, and writing that to enc.lua would break the install in
-- a way that's maddening to diagnose later. So check we actually got Lua.
local function looksLikeLua(body, label)
  if type(body) ~= "string" or #body == 0 then return false, "empty response" end
  local head = body:sub(1, 200):gsub("^%s+", "")
  if head:sub(1, 1) == "<" then
    return false, "got an HTML page, not Lua - wrong code/URL, or pastebin is " ..
      "blocking the request"
  end
  if body:find("Bad API request", 1, true) then
    return false, "pastebin rejected the request: " ..
      body:sub(1, 60):gsub("%s+$", "")
  end
  local fn, err = load(body, label)
  if not fn then return false, "downloaded file isn't valid Lua: " .. tostring(err) end
  return true
end

local function writeFile(destination, body)
  local parent = destination:match("^(.*)/[^/]*$")
  if parent and parent ~= "" and not fs.exists(parent) then fs.makeDir(parent) end
  local f = fs.open(destination, "w")
  f.write(body)
  f.close()
end

-- Tries each configured source in turn, so a partial BASE_URL plus a couple of
-- pastebin codes is a valid setup. Returns true, sourceName or false, err.
local function fetch(relativePath, destination)
  local attempts = {}

  if sourceDir then
    local from = fs.combine(sourceDir, relativePath)
    if fs.exists(from) then
      local parent = destination:match("^(.*)/[^/]*$")
      if parent and parent ~= "" and not fs.exists(parent) then fs.makeDir(parent) end
      if fs.exists(destination) then fs.delete(destination) end
      fs.copy(from, destination)
      return true, "local"
    end
    attempts[#attempts + 1] = "local (not present)"
  end

  if BASE_URL then
    -- raw.githubusercontent.com caches for several minutes, so a fresh push can
    -- otherwise install the previous version without any sign of it. The query
    -- string is ignored by the server but defeats the CDN cache.
    local body, err = httpFetch(BASE_URL .. relativePath ..
      "?cb=" .. tostring(os.epoch("utc")))
    if body then
      local ok, why = looksLikeLua(body, relativePath)
      if ok then
        writeFile(destination, body)
        return true, "url"
      end
      attempts[#attempts + 1] = "url (" .. why .. ")"
    else
      attempts[#attempts + 1] = "url (" .. err .. ")"
    end
  end

  local code = PASTEBIN[relativePath]
  if code then
    -- The cache-buster stops CC and pastebin's CDN serving a stale copy after
    -- you re-upload a file.
    local url = "https://pastebin.com/raw/" .. code ..
      "?cb=" .. tostring(os.epoch("utc"))
    local body, err = httpFetch(url)
    if body then
      local ok, why = looksLikeLua(body, relativePath)
      if ok then
        writeFile(destination, body)
        return true, "pastebin:" .. code
      end
      attempts[#attempts + 1] = "pastebin " .. code .. " (" .. why .. ")"
    else
      attempts[#attempts + 1] = "pastebin " .. code .. " (" .. err .. ")"
    end
  end

  if #attempts == 0 then
    return false, relativePath .. ": no source configured (set BASE_URL or a " ..
      "PASTEBIN code, or insert the install floppy)"
  end
  return false, relativePath .. ": " .. table.concat(attempts, "; ")
end

-- ---------------------------------------------------------------------------
-- Role and config
-- ---------------------------------------------------------------------------

local function chooseRole()
  local given = (args[1] or ""):lower()
  if ROLES[given] then return given end
  print("What is this computer?")
  print("  1) sGps position host")
  print("  2) helicopter autopilot")
  print("  3) operator console")
  print("  4) position watcher (prints coordinates as they change)")
  while true do
    write("Choice (1-4): ")
    local answer = (read() or ""):lower()
    if answer == "1" or answer == "host" then return "host" end
    if answer == "2" or answer == "heli" then return "heli" end
    if answer == "3" or answer == "pilot" then return "pilot" end
    if answer == "4" or answer == "watch" then return "watch" end
  end
end

local function askNumber(prompt, given)
  if given and tonumber(given) then return tonumber(given) end
  while true do
    write(prompt)
    local value = tonumber(read())
    if value then return value end
  end
end

local function askNumberList(prompt)
  write(prompt)
  local ids = {}
  for word in (read() or ""):gmatch("[^%s,]+") do
    local n = tonumber(word)
    if n then ids[#ids + 1] = n end
  end
  return ids
end

-- Each role script overlays this file over its inline defaults, so the
-- installer can configure a computer without anyone editing Lua.
local function writeConfig(path, config)
  local f = fs.open(path, "w")
  f.write(textutils.serialize(config))
  f.close()
end

local function configureHost()
  print("")
  print("This host's exact position, from F3. Everything the ships compute")
  print("rests on these being right.")
  local x = askNumber("  x: ", args[2])
  local y = askNumber("  y: ", args[3])
  local z = askNumber("  z: ", args[4])
  writeConfig("/host_config.tbl", {position = {x = x, y = y, z = z}})
  print("Saved position " .. x .. ", " .. y .. ", " .. z)
end

local function configureHeli()
  print("")
  print("Computer IDs of your sGps hosts, separated by spaces")
  print("(each host prints its own ID when it starts):")
  local hostIds = askNumberList("  hosts: ")
  print("Computer IDs allowed to command this ship:")
  local operatorIds = askNumberList("  operators: ")
  writeConfig("/heli_config.tbl", {gpsHostIds = hostIds, operatorIds = operatorIds})
  print("Saved " .. #hostIds .. " hosts, " .. #operatorIds .. " operators.")
  if #hostIds < 4 then
    print("NOTE: fewer than 4 hosts - sGps needs 4 for a fix by default.")
  end
end

local function configureWatch()
  -- Nothing to ask if this computer already has hosts pinned, or a ship config
  -- to borrow the list from.
  if fs.exists("/trusted_hosts.tbl") or fs.exists("/heli_config.tbl") then
    print("")
    print("Reusing the GPS hosts already known to this computer.")
    return
  end
  print("")
  print("Computer IDs of your sGps hosts, separated by spaces:")
  local hostIds = askNumberList("  hosts: ")
  writeConfig("/watch_config.tbl", {gpsHostIds = hostIds})
  print("Saved " .. #hostIds .. " hosts.")
  if #hostIds < 4 then
    print("NOTE: fewer than 4 hosts - sGps needs 4 for a fix by default.")
  end
end

local function configurePilot()
  print("")
  local shipId = askNumber("Computer ID of the helicopter: ", args[2])
  writeConfig("/pilot_config.tbl", {shipId = shipId})
  print("Saved ship ID " .. shipId .. ".")
  print("This computer is ID " .. os.getComputerID() ..
    " - authorise it on the ship.")
end

-- ---------------------------------------------------------------------------
-- Install
-- ---------------------------------------------------------------------------

local function countPastebinCodes()
  local n = 0
  for _ in pairs(PASTEBIN) do n = n + 1 end
  return n
end

print("sNav installer")
local sources = {}
if sourceDir then
  sources[#sources + 1] = (sourceDir == "" and "this computer" or sourceDir)
end
if BASE_URL then sources[#sources + 1] = BASE_URL end
local pasteCount = countPastebinCodes()
if pasteCount > 0 then sources[#sources + 1] = pasteCount .. " pastebin codes" end

if #sources == 0 then
  error("install.lua: nothing to install from. Either insert the install " ..
    "floppy, set BASE_URL, or fill in the PASTEBIN codes at the top of this " ..
    "file.", 0)
end
print("Sources: " .. table.concat(sources, ", "))

local role = chooseRole()
local roleScript = ROLES[role].script

print("")
print("Installing " .. ROLES[role].label .. "...")

local wanted = {}
for _, path in ipairs(LIBRARIES) do wanted[#wanted + 1] = path end
wanted[#wanted + 1] = roleScript
-- The helicopter is the only role that needs the navigation layer, but the
-- others are small and having them present makes a computer easy to repurpose.
-- The watcher and the diagnostic go everywhere: the moment you need them is
-- the moment the radio is misbehaving and downloading is awkward.
for _, path in ipairs(EXTRAS) do
  if path ~= roleScript then wanted[#wanted + 1] = path end
end

for _, path in ipairs(wanted) do
  local ok, info = fetch(path, "/" .. path)
  if not ok then
    print("")
    error("install.lua: " .. info, 0)
  end
  print("  " .. path .. "  (" .. info .. ")")
end

if role == "host" then configureHost()
elseif role == "heli" then configureHeli()
elseif role == "watch" then configureWatch()
else configurePilot() end

-- Boot straight into the role rather than leaving it to be run by hand.
local startup = fs.open("/startup.lua", "w")
startup.write('-- written by install.lua\nshell.run("/' .. roleScript .. '")\n')
startup.close()

print("")
print("Installed. This computer is ID " .. os.getComputerID() .. ".")
print("Remove the floppy, then reboot to start.")
