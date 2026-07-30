--[[
  publish.lua - uploads every file this system needs to pastebin and prints the
  PASTEBIN manifest to paste into install.lua.

  Run it on a computer that already has all the files (the one you developed
  on, or one installed from the floppy):

    publish

  It uses ComputerCraft's own `pastebin put`, so no API key is needed. Expect
  it to be slow and to occasionally fail: pastebin rate-limits guest uploads,
  and Cloudflare blocks CC's requests often enough that you may have to re-run
  it for the files that didn't make it. Codes for files that DID upload are
  printed as it goes, so nothing is lost when a later one fails.

  Output goes to the screen and to /pastebin_manifest.txt.

  If pastebin is being difficult, put the files in a GitHub repo instead and
  set BASE_URL in install.lua - one address covers every file, with no rate
  limits and no HTML error pages.
]]

local FILES = {
  "enc.lua",
  "sip.lua",
  "sgps/sGps.lua",
  "nav/sNav.lua",
  "gpshost.lua",
  "heli.lua",
  "pilot.lua"
}

assert(http, "publish.lua: HTTP is disabled on this server, so nothing can be uploaded")

-- `pastebin put` prints the code rather than returning it, so capture what it
-- writes. Hacky, but it avoids making you supply a pastebin API key.
local function uploadAndCaptureCode(path)
  local captured = {}
  local realPrint, realWrite = _G.print, _G.write
  _G.print = function(...)
    local parts = {}
    for i = 1, select("#", ...) do parts[#parts + 1] = tostring(select(i, ...)) end
    captured[#captured + 1] = table.concat(parts, " ")
    realPrint(...)
  end
  _G.write = function(text)
    captured[#captured + 1] = tostring(text)
    realWrite(text)
  end

  local ok, err = pcall(shell.run, "pastebin", "put", path)

  _G.print, _G.write = realPrint, realWrite
  if not ok then return nil, tostring(err) end

  local text = table.concat(captured, "\n")
  -- Matches both "Uploaded as https://pastebin.com/AbCd1234" and the
  -- "Run `pastebin get AbCd1234`" line that follows it.
  local code = text:match("pastebin%.com/([%w]+)") or text:match("get%s+([%w]+)")
  if not code then
    return nil, "uploaded, but the code couldn't be read from the output - " ..
      "check the screen and note it by hand"
  end
  return code
end

local results, failures = {}, {}

print("Uploading " .. #FILES .. " files to pastebin. This is slow.")
print("")

for _, path in ipairs(FILES) do
  local localPath = "/" .. path
  if not fs.exists(localPath) then
    print(path .. " -- MISSING on this computer, skipped")
    failures[#failures + 1] = path .. " (not present)"
  else
    write(path .. " ... ")
    local code, err = uploadAndCaptureCode(localPath)
    if code then
      results[path] = code
      print("  -> " .. code)
    else
      print("  FAILED: " .. tostring(err))
      failures[#failures + 1] = path .. " (" .. tostring(err) .. ")"
    end
    sleep(2) -- be gentle with the rate limiter
  end
end

-- ---- manifest -------------------------------------------------------------

local lines = {"local PASTEBIN = {"}
for _, path in ipairs(FILES) do
  if results[path] then
    lines[#lines + 1] = string.format('  [%q] = %q,', path, results[path])
  else
    lines[#lines + 1] = string.format('  -- [%q] = ???,  -- upload failed', path)
  end
end
lines[#lines + 1] = "}"
local manifest = table.concat(lines, "\n")

local f = fs.open("/pastebin_manifest.txt", "w")
f.write(manifest .. "\n")
f.close()

print("")
print("Paste this into install.lua, replacing its PASTEBIN table:")
print("")
print(manifest)
print("")
print("Also saved to /pastebin_manifest.txt")

if #failures > 0 then
  print("")
  print(#failures .. " file(s) failed:")
  for _, why in ipairs(failures) do print("  " .. why) end
  print("Re-run publish to retry them - codes above are still good.")
else
  print("")
  print("Now upload install.lua itself (with that table filled in):")
  print("  pastebin put /install.lua")
  print("Then every new computer is one command: pastebin run <that code>")
end
