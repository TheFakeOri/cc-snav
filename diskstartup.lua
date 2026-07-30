--[[
  diskstartup.lua - copy this onto the install floppy AS `startup.lua`:
    copy /diskstartup.lua /disk/startup.lua

  A computer that boots with this floppy in an attached drive installs itself.
  If it's already installed, this steps aside and lets the computer's own
  startup run, so you can leave the floppy in without it reinstalling on
  every reboot.
]]

local function findInstaller()
  for _, base in ipairs({"/disk", "/disk1", "/disk2", "/disk3", "/disk4", "/disk5", "/disk6"}) do
    if fs.exists(fs.combine(base, "install.lua")) then return fs.combine(base, "install.lua") end
  end
  return nil
end

local installer = findInstaller()
if not installer then return end

-- Already set up: don't touch it.
if fs.exists("/startup.lua") and fs.exists("/enc.lua") and fs.exists("/sip.lua") then
  print("Install floppy present, but this computer is already set up.")
  print("Remove the floppy, or run " .. installer .. " to reconfigure.")
  print("")
  return
end

shell.run(installer)
