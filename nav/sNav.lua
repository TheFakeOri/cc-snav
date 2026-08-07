--[[
  sNav.lua - Secure Navigation: autopilot for Create Aeronautics ships,
  flown by a ComputerCraft computer riding on the ship.

  Three layers, bottom to top:

    1. CONTROL - the computer emits analog redstone on its sides; Create
       Redstone Links carry those signals to the ship's actual thrust /
       rudder / elevator machinery. Six named controls (forward, reverse,
       yawLeft, yawRight, up, down) form three bidirectional axes:
       throttle, yaw, lift. Only `forward` and one yaw control are
       required - omit the rest and the autopilot adapts rather than
       commanding machinery that isn't there. See CONTROLS THE SHIP MAY
       NOT HAVE below, and the wiring notes at the end of this header.

    2. ESTIMATOR ("IMU-like") - sGps gives exact but SLOW position fixes
       (each one is several RSA operations plus network round trips to
       four hosts). A control loop can't wait on that every tick, so this
       layer does what a real inertial measurement unit does: between
       fixes it dead-reckons position forward from its last known
       velocity, and when a fix finally lands it corrects the prediction
       and re-derives velocity, speed, heading and yaw rate from the
       difference. Position comes from sGps; everything else is inferred.

    3. GUIDANCE - point-to-point autopilot. Turns toward the target,
       cruises, brakes using the learned deceleration, and holds altitude.
       Either driven locally (nav.flyTo) or remotely: another computer
       sends a destination over sip and this one flies there
       (nav.serveRemote / nav.sendCommand).

  LEARNING THE SHIP: no two Create Aeronautics ships handle alike, so the
  flight model (top speed, acceleration, braking, yaw rate, climb rate) is
  measured rather than assumed. nav.calibrate() flies a short scripted
  routine and records what the ship actually did; nav.saveModel() keeps it
  across reboots. Beyond that, every flight quietly refines the numbers -
  whenever the controls have been held steady long enough for the reading
  to mean something, the observed speed/turn rate is folded into the model
  with an exponential moving average.

  HEADING IS INFERRED FROM MOTION. A computer has no compass, so this
  library reads heading off the direction the ship is actually travelling.
  Consequence: heading is unknown while stationary (it reports the last
  known value), and a ship pivoting in place teaches the estimator
  nothing. That is why the autopilot keeps a little forward throttle on
  while turning instead of spinning on the spot - it needs the motion to
  see which way it is pointed. Headings follow Minecraft's yaw
  convention: degrees clockwise from south (+Z), so 0 = south, 90 = west,
  180 = north, -90 = east.

  CONTROLS THE SHIP MAY NOT HAVE. Leave an entry out of the control map and
  nav.capabilities() reports it missing; guidance, command clamping and
  calibration all consult that rather than assuming. Ready-made maps:
  nav.DEFAULT_CONTROL_MAP (everything), nav.CONTROL_MAP_NO_VERTICAL,
  nav.CONTROL_MAP_NO_REVERSE, nav.CONTROL_MAP_MINIMAL. What changes:

    - No `reverse`: the ship cannot thrust backwards, so its only way to
      slow down is to cut power and let drag do it. That is much weaker
      than active braking, so the approach is planned against
      model.coastDecel instead of model.decel - meaning the autopilot
      stops accelerating considerably earlier and coasts in. It never
      commands negative throttle. Expect longer, lazier arrivals; a ship
      with plenty of momentum and no brakes will overshoot if
      model.coastDecel is optimistic, so calibrate before trusting it.

    - No `up`/`down`: the ship holds whatever altitude its buoyancy gives
      it. The autopilot flies purely horizontally and treats the target's
      Y as information rather than an instruction - it will not hover
      waiting to reach an altitude it has no way to change. Give such
      ships targets at their own cruising height; a GOTO to y=200 from
      y=70 arrives at y=70, which is the honest outcome, not a failure.

    - Only `up` (buoyancy ships that rise under power and sink by venting,
      with no powered descent): it climbs to targets above it and simply
      arrives at targets below it. Same the other way round for `down`.

    - One yaw direction only: it steers the way it can and calibration
      measures the turn rate in that direction. Turns the other way take
      the long way round.

  STEPPED YAW (helicopter tails and similar). Some ships steer with an
  actuator whose ANGLE sets the turn rate rather than a rudder you hold
  over: rotate the tail one notch and it yaws left continuously; rotate it
  another notch and it yaws left faster; rotate it back to centre and the
  yaw stops. The rotation is an increment, and the mechanism remembers
  where it was left.

  Wire that with nav.CONTROL_MAP_STEPPED_YAW: a `yawStep` line pulsing a
  Create Sequenced Gearshift programmed "Turn by Angle: nav.YAW_STEP_ANGLE",
  and a `yawDirection` line driving a Gearshift that reverses the input so
  the same instruction steps the other way. nav.YAW_MAX_STEPS bounds how
  far from centre the autopilot will drive it.

  Consequences, all handled here but worth understanding:
    - "Stop yawing" is an ACTION, not the absence of one. nav.allStop()
      drives the tail back to centre before it finishes, because merely
      dropping the redstone lines would leave the ship turning forever.
      Everywhere the autopilot cuts controls for safety - arrival, abort,
      stale position, an operator STOP - therefore recentres the tail.
    - There is NO POSITION FEEDBACK. A Sequenced Gearshift reports nothing
      back, so the tracked deflection is dead-reckoned from the pulses
      sent. Call nav.assumeYawCentered() at startup with the tail actually
      centred; if that claim is wrong every later move inherits the error.
      nav.YAW_STEP_ANGLE likewise has to match what you programmed into the
      gearshift - nothing here can check it.
    - Yaw is quantised. With YAW_MAX_STEPS = 2 the continuous -1..1 yaw
      command collapses to five deflections, and the tail moves at most one
      step per guidance tick so each change can be observed before the next.
      nav.YAW_HYSTERESIS keeps a heading error sitting on a step boundary
      from pulsing the tail back and forth.
    - Pulses take real time (YAW_PULSE_TIME + YAW_SETTLE_TIME, plus
      YAW_DIRECTION_SETTLE on a reversal), and nav.setCommand blocks for
      them. Budget roughly half a second per step.

  STOPPING THE PROGRAM STOPS THE SHIP. The controls are redstone outputs, so
  they keep driving the machinery after the Lua that set them is gone - a
  Ctrl+T at full throttle would otherwise send the ship off with nobody
  steering. Every blocking entry point (nav.serveRemote, nav.calibrate,
  nav.flyTo) therefore runs through nav.withSafeShutdown, which catches the
  terminate, calls nav.allStop() - recentring a stepped tail on the way - and
  then re-raises, so Ctrl+T still ends the program. Wrap your own blocking
  loops the same way if they hold the controls:

    nav.withSafeShutdown(function() ... end)

  HONEST LIMITS:
    - Inherits every crypto caveat from enc.lua/sip.lua (toy RSA, RC4,
      weak randomness, non-cryptographic checksum) and every positioning
      caveat from sGps.
    - Fix latency dominates everything. Expect a fix every few seconds at
      best. Dead reckoning covers the gaps, but a ship that accelerates
      or turns hard between fixes will drift from the estimate until the
      next one arrives. Fly with margin; do not thread canyons with this.
    - nav.calibrate() deliberately flies the ship at full throttle in a
      straight line and then in a turn. Run it somewhere open, high, and
      far from anything you mind hitting. It skips whatever phases the
      ship isn't equipped for, so a minimal ship calibrates faster.
    - nav.acquire's optional nudge is the one place that deliberately leaves
      throttle on when it returns (calibration wants the ship already moving).
      Call it from inside nav.withSafeShutdown, or stop the ship yourself.
    - A ship that loses GPS quorum (jamming, out of range, hosts down)
      gets no fixes. The estimator keeps dead-reckoning and marks the
      state stale; the autopilot refuses to keep flying blind past
      nav.MAX_STALE_TIME and cuts throttle instead of guessing.
    - sGps talks raw modem on the computer-ID channel while sip talks
      rednet on the same channel. They coexist because each rejects the
      other's frame shapes, but don't add a third thing to that channel.

  Usage (on the ship):
    local nav = dofile("/sip/nav/sNav.lua")
    nav.sip.generateIdentity(256)        -- shared sip/sgps identity
    nav.sgps.open("back")
    for _, id in ipairs({12, 13, 14, 15}) do nav.sgps.trustHostById(id) end
    nav.setControlMap(nav.DEFAULT_CONTROL_MAP)   -- or your own wiring
    nav.loadModel("/ship.model")                 -- or nav.calibrate()
    nav.authorizeOperator(7)                     -- computer 7 may command us
    nav.serveRemote()                            -- blocks, flies on command

  Usage (operator computer):
    local nav = dofile("/sip/nav/sNav.lua")
    nav.sip.generateIdentity(256)
    nav.sip.open("back")
    local reply = nav.sendCommand(shipId, {cmd = "GOTO", x = 220, y = 96, z = -140})
    print(textutils.serialize(reply))

  Run `sNav.lua test` to exercise the estimator, guidance and model math
  directly - no modem, GPS hosts or ship required.

  ---------------------------------------------------------------------
  WIRING (also printed by `sNav.lua wiring`)

  Each of the computer's six sides drives one Create Redstone Link
  transmitter, tuned to its own frequency, paired with a receiver link on
  the ship next to the machinery it controls. Default map:

     front  -> forward thrust      back   -> reverse thrust
     left   -> yaw left (port)     right  -> yaw right (starboard)
     top    -> climb               bottom -> descend

  "front" is the side the computer's screen faces. Sides are relative to
  the computer, not to the ship - what matters is that each side reaches
  the right machinery, which is what the link frequencies decide.

  Per control:
    1. Place a Redstone Link against that side of the computer, set to
       TRANSMIT (links transmit by default; the wrench toggles mode).
    2. Put a matching pair of items in its two frequency slots. Every
       control needs a DIFFERENT pair, or one output will drive several
       systems at once.
    3. On the ship, place a Redstone Link with the SAME two items, set to
       RECEIVE, where its output feeds the machinery for that control.
    4. Both links must be part of the ship's assembled contraption if the
       ship moves relative to them - a link left on the ground stops
       matching the one that flew away.

  The signal is analog, 0-15, so it carries throttle level, not just
  on/off. Feed it into whatever reads strength on your build: a Rotational
  Speed Controller for propeller RPM, an Analog Lever's slot, a
  Sequenced Gearshift, or a comparator-driven gate. If your machinery only
  cares about on/off, any nonzero level reads as on and the extra
  resolution is simply unused.

  Short on sides, or wiring more than six controls? A control entry may
  carry a `color` field instead, e.g. {side = "back", color = colors.red};
  those go out as bundled cable on that side, sixteen controls per side,
  but bundled output is on/off only - no throttle levels.
  ---------------------------------------------------------------------
]]

local nav = {}

-- ===========================================================================
-- Module loading. sip and sGps must be the SAME sip instance: sGps reads the
-- identity out of sip (sip.getPrivateKey/getPublicKey), so a second, separate
-- sip copy would have no identity set and every sGps call would fail.
-- ===========================================================================

local function getScriptDir()
  local ok, info = pcall(debug.getinfo, 2, "S")
  if ok and info and info.source then
    local path = info.source:match("^@(.*)$") or info.source
    local dir = path:match("^(.*)[/\\][^/\\]*$")
    if dir and dir ~= "" then return dir end
  end
  return nil
end

local function findModule(name, relativePaths)
  local dir = getScriptDir()
  local candidates = {}
  if dir then
    for _, rel in ipairs(relativePaths) do
      candidates[#candidates + 1] = fs.combine(dir, rel)
    end
  end
  candidates[#candidates + 1] = name
  candidates[#candidates + 1] = "/" .. name
  candidates[#candidates + 1] = "/sip/" .. name
  for _, path in ipairs(candidates) do
    if fs.exists(path) then return dofile(path) end
  end
  return nil
end

nav.sip = findModule("sip.lua", {"../sip.lua", "sip.lua"})
assert(nav.sip, "sNav.lua: could not locate sip.lua (expected next to sNav.lua or one directory up)")

nav.sgps = findModule("sgps/sGps.lua", {"../sgps/sGps.lua", "sGps.lua", "sgps/sGps.lua"})
assert(nav.sgps, "sNav.lua: could not locate sGps.lua (expected in ../sgps/ or next to sNav.lua)")

nav.sgps.useSip(nav.sip) -- share one identity across both layers

local sip, sgps = nav.sip, nav.sgps

-- ===========================================================================
-- Tunables
-- ===========================================================================

nav.FIX_INTERVAL = 1.0      -- seconds between attempted sGps fixes
nav.MAX_STALE_TIME = 8      -- seconds without a fix before we refuse to fly on
nav.VELOCITY_ALPHA = 0.5    -- how hard a new fix overwrites the velocity estimate
nav.MODEL_ALPHA = 0.2       -- how hard a live observation overwrites the flight model
nav.MIN_SPEED_FOR_HEADING = 0.35 -- blocks/sec below which motion says nothing about heading

nav.ARRIVAL_RADIUS = 3      -- blocks (horizontal) that counts as "there"
nav.ARRIVAL_SPEED = 0.6     -- and slow enough to call it arrived
nav.VERTICAL_TOLERANCE = 1.5
nav.HEADING_TOLERANCE = 8   -- degrees; inside this we stop steering and cruise
nav.TURN_THROTTLE = 0.25    -- forward throttle held during a turn, so heading stays observable
nav.YAW_GAIN = 30           -- degrees of error that map to full yaw deflection

-- Stepped-yaw tuning (only used when the control map wires `yawStep`; see
-- STEPPED YAW in the header). YAW_STEP_ANGLE is documentation - it must match
-- the angle programmed into the Sequenced Gearshift, and nothing here can
-- verify that for you.
nav.YAW_STEP_ANGLE = 22       -- degrees of tail rotation per pulse
nav.YAW_MAX_STEPS = 2         -- steps from centre to full deflection, each way
nav.YAW_PULSE_TIME = 0.15     -- seconds the step line is held high
nav.YAW_SETTLE_TIME = 0.35    -- seconds for the gearshift to finish its turn
nav.YAW_DIRECTION_SETTLE = 0.1 -- seconds for the direction gearshift to flip
nav.YAW_HYSTERESIS = 0.25     -- extra margin past a step boundary before moving,
                              -- so a wandering heading error can't chatter the tail

-- Fallback flight model, used until nav.calibrate() or nav.loadModel()
-- replaces it. Deliberately timid - a wrong-but-slow guess is recoverable.
nav.DEFAULT_MODEL = {
  maxSpeed = 8,   -- blocks/sec at full throttle
  accel = 2,      -- blocks/sec^2
  decel = 2,      -- blocks/sec^2 under reverse thrust
  coastDecel = 1, -- blocks/sec^2 with the throttle simply cut (drag alone)
  yawRate = 20,   -- degrees/sec at full yaw deflection
  liftSpeed = 3   -- blocks/sec at full lift
}

-- Only `forward` and one yaw control are mandatory. Omit any other entry and
-- the autopilot adapts instead of commanding something the ship can't do:
-- see nav.capabilities().
nav.DEFAULT_CONTROL_MAP = {
  forward  = {side = "front"},
  reverse  = {side = "back"},
  yawLeft  = {side = "left"},
  yawRight = {side = "right"},
  up       = {side = "top"},
  down     = {side = "bottom"}
}

-- Ships with fixed-pitch lift (balloons, static buoyancy) that only steer and
-- drive: altitude is whatever the ship floats at, so the autopilot flies
-- purely horizontally and stops caring about target Y.
nav.CONTROL_MAP_NO_VERTICAL = {
  forward  = {side = "front"},
  reverse  = {side = "back"},
  yawLeft  = {side = "left"},
  yawRight = {side = "right"}
}

-- Single-direction propeller, no reverse: the ship slows by coasting, so the
-- autopilot begins braking much earlier, using the drag-only figure.
nav.CONTROL_MAP_NO_REVERSE = {
  forward  = {side = "front"},
  yawLeft  = {side = "left"},
  yawRight = {side = "right"},
  up       = {side = "top"},
  down     = {side = "bottom"}
}

-- Minimum viable airship: drive, steer, and nothing else.
nav.CONTROL_MAP_MINIMAL = {
  forward  = {side = "front"},
  yawLeft  = {side = "left"},
  yawRight = {side = "right"}
}

-- Helicopter with a stepped tail actuator: instead of two "hold this way"
-- lines, yaw has a pulse line (one pulse = one YAW_STEP_ANGLE step through a
-- Sequenced Gearshift) and a direction line (a Gearshift reversing the input,
-- powered = step toward starboard). See STEPPED YAW in the header.
nav.CONTROL_MAP_STEPPED_YAW = {
  forward      = {side = "front"},
  reverse      = {side = "back"},
  yawStep      = {side = "left"},
  yawDirection = {side = "right"},
  up           = {side = "top"},
  down         = {side = "bottom"}
}

-- ===========================================================================
-- State
-- ===========================================================================

local function freshEstimate()
  return {
    pos = nil,            -- {x,y,z}; nil until the first fix lands
    vel = {x = 0, y = 0, z = 0},
    speed = 0,            -- horizontal speed, blocks/sec
    heading = 0,          -- degrees clockwise from +Z, Minecraft yaw convention
    headingKnown = false,
    yawRate = 0,          -- degrees/sec, signed (positive = turning toward +heading)
    lastFixTime = nil,    -- os.clock() of the last accepted fix
    lastPredictTime = nil,
    fixCount = 0
  }
end

local state = {
  controlMap = nav.DEFAULT_CONTROL_MAP,
  model = nil,              -- filled in below
  estimate = freshEstimate(),
  command = {throttle = 0, yaw = 0, lift = 0},
  commandHeldSince = nil,   -- os.clock() when the current command last changed
  yawDeflection = 0,        -- stepped yaw only: tracked tail position, in steps.
                            -- Dead-reckoned from pulses sent - there is no
                            -- feedback from the mechanism, so this is only as
                            -- true as nav.assumeYawCentered() was when called.
  activeColors = {},        -- [side] = {[color] = true} for bundled outputs
  authorizedOperators = {}, -- [computerId] = true
  mission = nil,            -- {x,y,z} the autopilot is currently flying to
  lastError = nil
}

do -- start from a copy of the default model, never the shared table itself
  state.model = {}
  for k, v in pairs(nav.DEFAULT_MODEL) do state.model[k] = v end
end

function nav.getModel()
  local copy = {}
  for k, v in pairs(state.model) do copy[k] = v end
  return copy
end

function nav.setModel(model)
  for k, v in pairs(model) do
    if type(v) == "number" then state.model[k] = v end
  end
end

function nav.getState()
  local e = state.estimate
  return {
    pos = e.pos and {x = e.pos.x, y = e.pos.y, z = e.pos.z} or nil,
    vel = {x = e.vel.x, y = e.vel.y, z = e.vel.z},
    speed = e.speed,
    heading = e.heading,
    headingKnown = e.headingKnown,
    yawRate = e.yawRate,
    fixCount = e.fixCount,
    fixAge = e.lastFixTime and (os.clock() - e.lastFixTime) or nil,
    mission = state.mission and {x = state.mission.x, y = state.mission.y, z = state.mission.z} or nil,
    command = {throttle = state.command.throttle, yaw = state.command.yaw, lift = state.command.lift},
    yawDeflection = state.yawDeflection,
    lastError = state.lastError
  }
end

-- ===========================================================================
-- Control layer: analog redstone out to Create Redstone Links.
-- ===========================================================================

-- Memoised nav.capabilities() result. Only the control map decides it, so it is
-- rebuilt lazily and dropped by setControlMap rather than recomputed per tick.
local capabilityCache = nil

function nav.setControlMap(map)
  assert(type(map) == "table" and map.forward,
    "nav.setControlMap: a `forward` control is mandatory - a ship with no way " ..
    "to drive itself cannot be navigated")
  assert(map.yawLeft or map.yawRight or map.yawStep,
    "nav.setControlMap: a yaw control is mandatory (yawLeft/yawRight for a held " ..
    "rudder, or yawStep for a stepped tail actuator) - a ship with no way to " ..
    "steer cannot be navigated")
  -- A stepped tail with no way to step back could never return to centre, so it
  -- could never stop yawing. Refuse that wiring rather than discover it in
  -- flight, when allStop would silently fail to recentre.
  assert((not map.yawStep) or map.yawDirection,
    "nav.setControlMap: a stepped yaw actuator (yawStep) also needs yawDirection - " ..
    "without a way to reverse the steps the tail could never return to centre, " ..
    "and the ship could never stop turning")
  nav.allStop()
  state.controlMap = map
  state.activeColors = {}
  state.yawDeflection = 0
  capabilityCache = nil -- the wiring changed, so what the ship can do changed
end

-- What this ship can actually be told to do, derived from which controls are
-- wired. Everything downstream - command clamping, guidance, calibration -
-- reads this rather than assuming a fully-equipped ship.
--
-- The result is CACHED and shared, because nav.setCommand asks for it on every
-- guidance tick and the answer only changes when the wiring does. Treat it as
-- read-only; nav.setControlMap invalidates it. (Callers that want to reason
-- about a hypothetical ship pass their own table as opts.capabilities instead.)
function nav.capabilities()
  if capabilityCache then return capabilityCache end
  local m = state.controlMap or {}
  local stepped = m.yawStep ~= nil
  capabilityCache = {
    forward  = m.forward ~= nil,
    reverse  = m.reverse ~= nil,
    yawMode  = stepped and "stepped" or "level",
    -- setControlMap guarantees a stepped tail has its direction line, so a
    -- stepped ship can always steer both ways.
    yawLeft  = stepped or (m.yawLeft ~= nil),
    yawRight = stepped or (m.yawRight ~= nil),
    climb    = m.up ~= nil,
    descend  = m.down ~= nil,
    vertical = (m.up ~= nil) or (m.down ~= nil)
  }
  return capabilityCache
end

local function clamp(v, lo, hi)
  if v < lo then return lo end
  if v > hi then return hi end
  return v
end

-- 0..1 magnitude -> 0..15 redstone strength
local function levelFor(magnitude)
  return math.floor(clamp(magnitude, 0, 1) * 15 + 0.5)
end

-- Splits a signed axis value across its two opposing controls. Exactly one
-- side of an axis is ever driven; the other is explicitly zeroed, so a
-- reversal can't briefly command thrust in both directions at once.
local function axisOutputs(value, positiveName, negativeName)
  local level = levelFor(math.abs(value))
  if value > 0 then
    return {[positiveName] = level, [negativeName] = 0}
  elseif value < 0 then
    return {[positiveName] = 0, [negativeName] = level}
  end
  return {[positiveName] = 0, [negativeName] = 0}
end

local function emit(controlName, level)
  local ctrl = state.controlMap and state.controlMap[controlName]
  if not ctrl then return end
  if ctrl.color then
    local active = state.activeColors[ctrl.side] or {}
    state.activeColors[ctrl.side] = active
    active[ctrl.color] = (level > 0) or nil
    local mask = 0
    for color in pairs(active) do mask = mask + color end
    redstone.setBundledOutput(ctrl.side, mask)
  else
    redstone.setAnalogOutput(ctrl.side, level)
  end
end

-- The same splitting policy as axisOutputs, driven straight out to the two
-- controls instead of through a throwaway table. nav.setCommand runs this three
-- times per guidance tick, and with the fast enc.lua the guidance loop turns
-- over often enough that a table (plus its `pairs` iteration) per axis per tick
-- is real garbage for no benefit.
--
-- The idle side is zeroed BEFORE the active side is raised, so a thrust
-- reversal can never momentarily drive both directions at once - the old
-- `pairs` loop emitted in whatever order the hash landed in, so half the time
-- it raised the new direction first.
local function emitAxis(value, positiveName, negativeName)
  local level = levelFor(value < 0 and -value or value)
  if value > 0 then
    emit(negativeName, 0)
    emit(positiveName, level)
  elseif value < 0 then
    emit(positiveName, 0)
    emit(negativeName, level)
  else
    emit(positiveName, 0)
    emit(negativeName, 0)
  end
end

-- Zeroes out any component this ship has no control for, so an unequipped
-- axis reads as a real zero everywhere downstream (telemetry, the learning
-- pass, the operator's STATUS reply) rather than as a command that silently
-- went nowhere.
local function clampToCapabilities(throttle, yaw, lift, caps)
  if throttle < 0 and not caps.reverse then throttle = 0 end
  if yaw > 0 and not caps.yawRight then yaw = 0 end
  if yaw < 0 and not caps.yawLeft then yaw = 0 end
  if lift > 0 and not caps.climb then lift = 0 end
  if lift < 0 and not caps.descend then lift = 0 end
  return throttle, yaw, lift
end

-- ---------------------------------------------------------------------------
-- Stepped yaw: a tail whose ANGLE sets the turn rate, moved by discrete
-- pulses. Unlike a held rudder, this actuator remembers where it was left, so
-- "stop yawing" means actively driving it back to centre - never just dropping
-- the outputs.
-- ---------------------------------------------------------------------------

-- Which deflection to move to, given the commanded yaw and where the tail is
-- now. Moves at most ONE step per call: each guidance tick nudges the tail and
-- then gets to observe the result, rather than slamming to full deflection
-- before the next fix reveals what that did. The hysteresis band means a
-- heading error hovering on a step boundary won't pulse the tail back and
-- forth. Pure, so the stepping policy is testable.
local function targetDeflectionFor(yaw, current, maxSteps, hysteresis)
  local desired = yaw * maxSteps
  local target = current
  if desired > current + 0.5 + hysteresis then
    target = current + 1
  elseif desired < current - 0.5 - hysteresis then
    target = current - 1
  end
  return clamp(target, -maxSteps, maxSteps)
end

-- Emits one pulse, moving the tail a single step. `dir` is +1 toward starboard.
local function pulseYawStep(dir)
  local map = state.controlMap or {}
  if not map.yawStep then return false end
  if map.yawDirection then
    emit("yawDirection", dir > 0 and 15 or 0)
    sleep(nav.YAW_DIRECTION_SETTLE)
  elseif dir < 0 then
    return false -- no direction line: this mechanism only steps one way
  end
  emit("yawStep", 15)
  sleep(nav.YAW_PULSE_TIME)
  emit("yawStep", 0)
  sleep(nav.YAW_SETTLE_TIME)
  state.yawDeflection = state.yawDeflection + dir
  return true
end

-- Declares the tail to be physically centred right now, without moving it.
-- Call this at startup with the tail actually centred: there is no position
-- feedback from a Sequenced Gearshift, so every later move is dead-reckoned
-- from this claim. Get it wrong and the autopilot will steer confidently
-- against an offset it cannot see.
function nav.assumeYawCentered()
  state.yawDeflection = 0
end

function nav.getYawDeflection() return state.yawDeflection end

-- Drives the tail back to centre, one step at a time. Returns true if it got
-- there (a one-way mechanism with positive deflection cannot).
function nav.centerYaw()
  local guard = 2 * nav.YAW_MAX_STEPS + 2 -- never loop forever on a stuck actuator
  while state.yawDeflection ~= 0 and guard > 0 do
    local dir = state.yawDeflection > 0 and -1 or 1
    if not pulseYawStep(dir) then return false end
    guard = guard - 1
  end
  return state.yawDeflection == 0
end

-- throttle/yaw/lift are all -1..1. Positive throttle is forward, positive
-- yaw steers toward increasing heading (clockwise from above, i.e. to
-- starboard under the Minecraft yaw convention), positive lift climbs.
-- Components the ship isn't wired for are dropped rather than faked.
function nav.setCommand(throttle, yaw, lift)
  throttle, yaw, lift = clamp(throttle, -1, 1), clamp(yaw, -1, 1), clamp(lift, -1, 1)
  local caps = nav.capabilities()
  throttle, yaw, lift = clampToCapabilities(throttle, yaw, lift, caps)

  emitAxis(throttle, "forward", "reverse")
  emitAxis(lift, "up", "down")

  if caps.yawMode == "stepped" then
    -- Guard the divisor: YAW_MAX_STEPS is an operator tunable, and a zero there
    -- would turn the reported yaw into a NaN that poisons the learning pass and
    -- every telemetry reply after it.
    local maxSteps = nav.YAW_MAX_STEPS
    if not (maxSteps and maxSteps >= 1) then maxSteps = 1 end
    local target = targetDeflectionFor(yaw, state.yawDeflection, maxSteps,
      nav.YAW_HYSTERESIS)
    if target ~= state.yawDeflection then
      pulseYawStep(target > state.yawDeflection and 1 or -1)
    end
    -- The effective yaw command is where the tail actually sits, not what was
    -- asked for, so telemetry and the learning pass see the real deflection.
    yaw = state.yawDeflection / maxSteps
  else
    emitAxis(yaw, "yawRight", "yawLeft")
  end

  local command = state.command
  local changed = throttle ~= command.throttle or yaw ~= command.yaw or
    lift ~= command.lift
  command.throttle, command.yaw, command.lift = throttle, yaw, lift
  if changed then state.commandHeldSince = os.clock() end
end

local THRUST_CONTROLS = {"forward", "reverse", "up", "down"}

function nav.allStop()
  local map = state.controlMap or {}
  -- Stop pushing first, then deal with the tail, so a ship that is about to
  -- lose its steering at least isn't accelerating while it does. This ordering
  -- also matters on the terminate path: if a second Ctrl+T lands inside the
  -- stepped-tail recentre below (it sleeps, so it can be interrupted), thrust is
  -- already at zero by then.
  for i = 1, #THRUST_CONTROLS do
    local name = THRUST_CONTROLS[i]
    if map[name] then emit(name, 0) end
  end
  -- A stepped tail holds its last angle mechanically. Dropping the lines here
  -- would leave the ship yawing indefinitely, so centre it deliberately.
  if map.yawStep then
    nav.centerYaw()
    emit("yawStep", 0)
    emit("yawDirection", 0)
  else
    if map.yawLeft then emit("yawLeft", 0) end
    if map.yawRight then emit("yawRight", 0) end
  end
  local command = state.command
  command.throttle, command.yaw, command.lift = 0, 0, 0
  state.commandHeldSince = os.clock()
end

-- ---------------------------------------------------------------------------
-- Guaranteed shutdown.
--
-- This library holds analog redstone outputs that drive real thrust through
-- Create Redstone Links, so "the program stopped" and "the ship stopped" are
-- two different events. Ctrl+T arrives as error("Terminated", 0) out of
-- whichever pull happened to be blocking - and terminate bypasses event
-- filters, so that can be any sleep or receive anywhere in the call tree. Left
-- unhandled it unwinds straight past every cleanup path, leaving the throttle
-- high, a stepped tail still deflected, and nobody steering.
--
-- So catch it deliberately, here, at the one place that owns the outputs:
-- nav.allStop() always runs (which recentres a stepped tail), and then the
-- original error is RE-RAISED. That last part is what keeps the program
-- killable - a blanket pcall that swallowed "Terminated" would make Ctrl+T do
-- nothing, which is a worse failure than the one being fixed. Genuine bugs
-- likewise still reach the player: re-raising at level 0 keeps the message
-- exactly as it was thrown, rather than stapling this file's line number over
-- the crash site's. (pcall cannot preserve a traceback; if you are chasing one,
-- call the *Leg/*Run/*Loop function under xpcall yourself.)
--
-- Wrap anything that blocks while holding the controls: nav.serveRemote,
-- nav.calibrate and nav.flyTo all go through this.
function nav.withSafeShutdown(body, ...)
  local results = table.pack(pcall(body, ...))

  -- Looked up through `nav` on purpose, so the self-test can substitute a
  -- counter and prove this path really does cut the controls.
  local stopped, stopErr = pcall(nav.allStop)
  if not stopped then
    -- The only thing in allStop that can fail is the stepped-tail recentre, and
    -- the likely cause is a second terminate landing inside its sleeps. Thrust
    -- is already down; try once more to unwind the tail so the ship is not left
    -- turning, but do not loop on it - a held Ctrl+T must still get through.
    pcall(nav.allStop)
  end
  state.mission = nil

  if not results[1] then error(results[2], 0) end
  if not stopped then error(stopErr, 0) end
  return table.unpack(results, 2, results.n)
end

-- ===========================================================================
-- Geometry / model helpers (pure)
-- ===========================================================================

-- Wraps to (-180, 180].
local function normalizeAngle(deg)
  deg = deg % 360
  if deg > 180 then deg = deg - 360 end
  return deg
end

-- Minecraft yaw: 0 = +Z (south), 90 = -X (west), 180 = -Z (north), -90 = +X (east).
local function headingFromVelocity(vx, vz)
  return normalizeAngle(math.deg(math.atan2(-vx, vz)))
end

local function bearingTo(from, to)
  return headingFromVelocity(to.x - from.x, to.z - from.z)
end

local function horizontalDistance(a, b)
  local dx, dz = b.x - a.x, b.z - a.z
  return math.sqrt(dx * dx + dz * dz)
end

-- How far this ship needs to start slowing down: the kinematic braking
-- distance, plus however far it travels during one fix interval, since the
-- decision to brake can only ever be made on information that stale.
local function brakingDistance(speed, decel, latency)
  if decel <= 0 then return math.huge end
  return (speed * speed) / (2 * decel) + speed * (latency or 0)
end

-- ===========================================================================
-- Estimator: dead reckoning between fixes, correction when one arrives.
-- Pure functions over an estimate table so they're testable without a modem.
-- ===========================================================================

-- Advances the estimate to time `now` using the last known velocity.
local function predict(e, now)
  if not e.pos or not e.lastPredictTime then
    e.lastPredictTime = now
    return e
  end
  local dt = now - e.lastPredictTime
  if dt <= 0 then return e end
  e.pos.x = e.pos.x + e.vel.x * dt
  e.pos.y = e.pos.y + e.vel.y * dt
  e.pos.z = e.pos.z + e.vel.z * dt
  e.heading = normalizeAngle(e.heading + e.yawRate * dt)
  e.lastPredictTime = now
  return e
end

-- Folds a real sGps fix in: position is taken from the fix outright (it is
-- ground truth, unlike our extrapolation), while velocity, heading and yaw
-- rate are re-derived from how far the ship actually moved since the last
-- fix and blended with the running estimate.
local function fuseFix(e, fix, now, alpha)
  -- fixPos is only ever written alongside pos and lastFixTime, so all three
  -- travel together - but require it explicitly rather than dereferencing it on
  -- faith, because an estimate assembled by hand (a test, a restored snapshot)
  -- would otherwise crash here instead of just starting cold.
  if e.pos and e.lastFixTime and e.fixPos then
    local dt = now - e.lastFixTime
    if dt > 1e-6 then
      local mvx = (fix.x - e.fixPos.x) / dt
      local mvy = (fix.y - e.fixPos.y) / dt
      local mvz = (fix.z - e.fixPos.z) / dt
      e.vel.x = e.vel.x + alpha * (mvx - e.vel.x)
      e.vel.y = e.vel.y + alpha * (mvy - e.vel.y)
      e.vel.z = e.vel.z + alpha * (mvz - e.vel.z)

      local speed = math.sqrt(e.vel.x * e.vel.x + e.vel.z * e.vel.z)
      e.speed = speed
      if speed >= nav.MIN_SPEED_FOR_HEADING then
        local newHeading = headingFromVelocity(e.vel.x, e.vel.z)
        if e.headingKnown then
          e.yawRate = normalizeAngle(newHeading - e.heading) / dt
        else
          e.yawRate = 0
        end
        e.heading = newHeading
        e.headingKnown = true
      else
        -- Too slow for the direction of travel to mean anything; keep the
        -- last known heading rather than inventing one from noise.
        e.yawRate = 0
      end
    end
  else
    e.speed = 0
    e.yawRate = 0
  end

  e.pos = {x = fix.x, y = fix.y, z = fix.z}
  e.fixPos = {x = fix.x, y = fix.y, z = fix.z}
  e.lastFixTime = now
  e.lastPredictTime = now
  e.fixCount = e.fixCount + 1
  return e
end

-- Refines the flight model from what the ship is actually doing, but only
-- when the current command has been held long enough for the reading to
-- reflect it rather than the previous command's momentum.
-- Hoisted out of learnFromObservation rather than closed over its arguments:
-- learning runs on every accepted fix, and a fresh closure per call was pure
-- per-tick garbage.
local function blendToward(model, key, observed, alpha)
  if observed and observed > 0 then
    model[key] = model[key] + alpha * (observed - model[key])
  end
end

local function learnFromObservation(model, e, command, heldFor, alpha)
  if heldFor < 2 then return model end
  if command.throttle >= 0.95 and e.speed > 0 then
    blendToward(model, "maxSpeed", e.speed, alpha)
  end
  if math.abs(command.yaw) >= 0.95 and e.headingKnown then
    blendToward(model, "yawRate", math.abs(e.yawRate), alpha)
  end
  if math.abs(command.lift) >= 0.95 then
    blendToward(model, "liftSpeed", math.abs(e.vel.y), alpha)
  end
  return model
end

nav._internal = {
  normalizeAngle = normalizeAngle,
  headingFromVelocity = headingFromVelocity,
  bearingTo = bearingTo,
  horizontalDistance = horizontalDistance,
  brakingDistance = brakingDistance,
  predict = predict,
  fuseFix = fuseFix,
  learnFromObservation = learnFromObservation,
  axisOutputs = axisOutputs,
  levelFor = levelFor,
  freshEstimate = freshEstimate,
  clampToCapabilities = clampToCapabilities,
  targetDeflectionFor = targetDeflectionFor
}

-- ===========================================================================
-- Estimator driver (needs sGps)
-- ===========================================================================

function nav.resetEstimate()
  state.estimate = freshEstimate()
end

-- Attempts one sGps fix and folds it in. Returns true if a fix landed, or
-- false, err.
--
-- sgps.locate does not always fail politely: no modem open, or fewer trusted
-- hosts than minFixes, and it RAISES instead of returning nil, err. Unprotected
-- that error unwound through nav.step, out of the flight loop, and past every
-- place that cuts the throttle - a configuration mistake became a runaway ship.
-- A fix that cannot be taken is exactly the condition the autopilot already
-- handles (the estimate goes stale and flyTo stops the ship deliberately), so
-- turn the exception into that instead, keeping the real reason in lastError -
-- which nav.getState and the STATUS reply both expose.
function nav.fix(opts)
  local ok, x, y, z, err = pcall(sgps.locate, opts)
  if not ok then
    state.lastError = tostring(x)
    return false, state.lastError
  end
  if not x then
    state.lastError = err
    return false, err
  end
  fuseFix(state.estimate, {x = x, y = y, z = z}, os.clock(), nav.VELOCITY_ALPHA)
  state.lastError = nil
  return true
end

-- The work half of nav.step, without the state snapshot. Most callers (acquire,
-- calibration, the idle branch of serveRemote) threw that snapshot away, which
-- cost six tables each time round.
local function stepEstimator()
  local e = state.estimate
  local now = os.clock()
  predict(e, now)

  if (not e.lastFixTime) or (now - e.lastFixTime) >= nav.FIX_INTERVAL then
    nav.fix()
    local heldSince = state.commandHeldSince
    if heldSince then
      -- Deliberately re-reads the clock: nav.fix blocks for network round trips
      -- plus RSA, so `now` is measurably stale by here and would understate how
      -- long the command has actually been held.
      learnFromObservation(state.model, e, state.command,
        os.clock() - heldSince, nav.MODEL_ALPHA)
    end
  end
end

-- One estimator tick: extrapolate to now, take a fresh fix if one is due,
-- and let the flight model learn from whatever the ship is currently doing.
function nav.step()
  stepEstimator()
  return nav.getState()
end

function nav.isStale()
  local e = state.estimate
  if not e.lastFixTime then return true end
  return (os.clock() - e.lastFixTime) > nav.MAX_STALE_TIME
end

-- Blocks until the estimator has a position and a usable heading, or until
-- timeout. A ship that has never moved has no heading, so this optionally
-- nudges the throttle to create some motion to read.
function nav.acquire(timeout, nudge)
  local deadline = os.clock() + (timeout or 30)
  while os.clock() < deadline do
    stepEstimator()
    local e = state.estimate
    if e.pos and (e.headingKnown or not nudge) then return true end
    if nudge and e.pos and not e.headingKnown then
      nav.setCommand(nav.TURN_THROTTLE, 0, 0)
    end
    sleep(0.2)
  end
  if nudge then nav.allStop() end
  return false, "acquire_timeout"
end

-- ===========================================================================
-- Guidance (pure decision function, so the autopilot's judgement is testable)
-- ===========================================================================

-- Returns a command table {throttle, yaw, lift, arrived, phase}. `phase` is
-- purely for logging/telemetry.
function nav.guidanceCommand(st, target, model, opts)
  opts = opts or {}
  local caps = opts.capabilities or nav.capabilities()
  local arrivalRadius = opts.arrivalRadius or nav.ARRIVAL_RADIUS
  local verticalTolerance = opts.verticalTolerance or nav.VERTICAL_TOLERANCE
  local headingTolerance = opts.headingTolerance or nav.HEADING_TOLERANCE
  local latency = opts.latency or nav.FIX_INTERVAL

  if not st.pos then
    return {throttle = 0, yaw = 0, lift = 0, arrived = false, phase = "no_position"}
  end

  local dist = horizontalDistance(st.pos, target)
  local dy = target.y - st.pos.y

  -- Vertical is independent of heading, so it runs the whole time - but only
  -- in the directions this ship can actually move. A lift-only ship can climb
  -- to its target but can never come back down under power.
  local canCorrectAltitude = math.abs(dy) > verticalTolerance and
    ((dy > 0 and caps.climb) or (dy < 0 and caps.descend))
  local lift = 0
  if canCorrectAltitude then
    lift = clamp(dy / math.max(model.liftSpeed, 0.1), -1, 1)
  end

  -- Altitude only gates arrival if we have some way to change it. Otherwise
  -- the target's Y is a fact about the world, not an instruction, and holding
  -- station waiting for it would mean hovering forever.
  local altitudeSettled = not canCorrectAltitude

  if dist <= arrivalRadius and st.speed <= (opts.arrivalSpeed or nav.ARRIVAL_SPEED)
     and altitudeSettled then
    return {throttle = 0, yaw = 0, lift = 0, arrived = true, phase = "arrived"}
  end

  -- Close enough horizontally but still climbing/descending: hold station.
  if dist <= arrivalRadius then
    return {throttle = 0, yaw = 0, lift = lift, arrived = false, phase = "station_keeping"}
  end

  local bearing = bearingTo(st.pos, target)
  local headingError = normalizeAngle(bearing - st.heading)

  -- Lead the turn: by the time we act on this, the ship will already have
  -- swung further at its current yaw rate, so steer against that.
  local effectiveError = headingError - st.yawRate * latency
  local yaw = clamp(effectiveError / nav.YAW_GAIN, -1, 1)

  -- Without reverse thrust the only way to slow down is to stop pushing and
  -- let drag do it, which is much weaker - so the stopping distance is longer
  -- and the decision to quit accelerating has to come sooner.
  local brakeDecel = caps.reverse and model.decel or (model.coastDecel or model.decel)
  local brakeDist = brakingDistance(st.speed, brakeDecel, latency)

  local throttle, phase
  if not st.headingKnown then
    -- No heading yet: creep forward so the estimator can see which way we
    -- point, and don't steer on a heading we don't have.
    throttle, yaw, phase = nav.TURN_THROTTLE, 0, "seeking_heading"
  elseif dist <= brakeDist then
    if caps.reverse then
      throttle, phase = -0.5, "braking"
    else
      throttle, phase = 0, "coasting"
    end
  elseif math.abs(headingError) > headingTolerance then
    throttle, phase = nav.TURN_THROTTLE, "turning"
  else
    throttle, phase = 1, "cruising"
    yaw = clamp(effectiveError / nav.YAW_GAIN, -0.4, 0.4) -- gentle trim only
  end

  throttle, yaw, lift = clampToCapabilities(throttle, yaw, lift, caps)
  return {throttle = throttle, yaw = yaw, lift = lift, arrived = false, phase = phase}
end

-- ===========================================================================
-- Autopilot
-- ===========================================================================

-- Flies to target, blocking until arrival, timeout, cancellation or a
-- refusal to continue on stale position data. opts.shouldAbort is polled
-- each iteration; return true from it to break off the flight.
-- Returns true on arrival, or false, err.
local function flyToLeg(target, opts)
  opts = opts or {}
  local deadline = opts.timeout and (os.clock() + opts.timeout) or nil
  local shouldAbort, onTick = opts.shouldAbort, opts.onTick
  local tickInterval = opts.tickInterval or 0.25
  local model = state.model -- setModel mutates in place, so this stays current
  state.mission = {x = target.x, y = target.y, z = target.z}

  local function finish(ok, err)
    nav.allStop()
    state.mission = nil
    return ok, err
  end

  while true do
    if shouldAbort and shouldAbort() then return finish(false, "aborted") end
    if deadline and os.clock() > deadline then return finish(false, "timeout") end

    -- nav.step already builds the snapshot guidance needs; the old code threw
    -- that one away and built a second identical one.
    local st = nav.step()

    -- st.fixAge is exactly the measurement nav.isStale() would go back to the
    -- clock for. Same test, one less clock read and no second traversal.
    if (not st.fixAge) or st.fixAge > nav.MAX_STALE_TIME then
      -- Flying on dead reckoning alone past this point is guessing with a
      -- ship. Stop and let the caller decide.
      return finish(false, "position_stale")
    end

    local cmd = nav.guidanceCommand(st, target, model, opts)
    if cmd.arrived then return finish(true) end
    nav.setCommand(cmd.throttle, cmd.yaw, cmd.lift)
    if onTick then onTick(st, cmd) end

    sleep(tickInterval)
  end
end

function nav.flyTo(target, opts)
  -- The sleep at the bottom of the leg is a filtered pull, so Ctrl+T surfaces
  -- there as an error and would otherwise skip `finish` entirely.
  return nav.withSafeShutdown(flyToLeg, target, opts)
end

-- ===========================================================================
-- Calibration: fly a short scripted routine and measure what the ship did.
-- ===========================================================================

local function sampleSpeedUnder(command, duration, settleTime)
  nav.setCommand(command.throttle or 0, command.yaw or 0, command.lift or 0)
  local settleUntil = os.clock() + (settleTime or 0)
  local deadline = os.clock() + duration
  local samples, headingSamples = {}, {}
  while os.clock() < deadline do
    stepEstimator()
    if os.clock() >= settleUntil then
      local e = state.estimate
      samples[#samples + 1] = {speed = e.speed, vy = e.vel.y}
      if e.headingKnown then headingSamples[#headingSamples + 1] = e.yawRate end
    end
    sleep(0.25)
  end
  return samples, headingSamples
end

local function mean(values)
  if #values == 0 then return nil end
  local sum = 0
  for _, v in ipairs(values) do sum = sum + v end
  return sum / #values
end

-- Times how long the ship takes to fall to near-stop under `throttle`, and
-- converts that into an average deceleration. Returns nil if it never stopped
-- inside the window, which is itself worth knowing.
local function measureDeceleration(throttle, startSpeed, window)
  if startSpeed <= nav.ARRIVAL_SPEED then return nil end
  local started = os.clock()
  nav.setCommand(throttle, 0, 0)
  local deadline = started + window
  while os.clock() < deadline do
    stepEstimator()
    if state.estimate.speed <= nav.ARRIVAL_SPEED then
      local elapsed = os.clock() - started
      if elapsed > 0 then return startSpeed / elapsed end
      return nil
    end
    sleep(0.25)
  end
  return nil
end

-- Brings the ship up to full speed and returns the speed it settled at.
local function runUpToSpeed(legTime, settle)
  local samples = sampleSpeedUnder({throttle = 1}, legTime, settle)
  local speeds = {}
  for _, s in ipairs(samples) do speeds[#speeds + 1] = s.speed end
  return mean(speeds)
end

-- Measures top speed, acceleration, coasting and braking deceleration, yaw
-- rate and climb rate - skipping whatever this ship isn't wired for. THIS
-- FLIES THE SHIP AT FULL THROTTLE - run it somewhere open and high.
-- Returns the learned model, or nil, err.
local function calibrationRun(opts)
  opts = opts or {}
  local legTime = opts.legTime or 8
  local settle = opts.settleTime or 3
  local caps = nav.capabilities()

  local ok, err = nav.acquire(opts.acquireTimeout or 30, true)
  if not ok then
    nav.allStop()
    return nil, err or "no_position"
  end

  local model = nav.getModel()

  -- Straight-line run: steady-state speed at full throttle.
  local topSpeed = runUpToSpeed(legTime, settle)
  if topSpeed and topSpeed > 0 then model.maxSpeed = topSpeed end

  -- Acceleration: from a standstill, how long to reach most of that speed.
  nav.allStop()
  sleep(opts.restTime or 4)
  stepEstimator()
  local accelStart = os.clock()
  nav.setCommand(1, 0, 0)
  local reached = nil
  local accelDeadline = os.clock() + legTime
  while os.clock() < accelDeadline do
    stepEstimator()
    if model.maxSpeed and state.estimate.speed >= 0.6 * model.maxSpeed then
      reached = os.clock() - accelStart
      break
    end
    sleep(0.25)
  end
  if reached and reached > 0 and model.maxSpeed then
    model.accel = (0.6 * model.maxSpeed) / reached
  end

  -- Coasting: cut thrust entirely and let drag do the work. Measured for
  -- every ship, because it's the only braking a ship without reverse thrust
  -- has, and the autopilot plans its approach around this number.
  local coastDecel = measureDeceleration(0, state.estimate.speed, legTime * 3)
  if coastDecel and coastDecel > 0 then model.coastDecel = coastDecel end

  -- Active braking under reverse thrust, if this ship has any. Needs another
  -- run-up first, since coasting already brought it to a stop.
  if caps.reverse then
    nav.allStop()
    sleep(opts.restTime or 4)
    runUpToSpeed(legTime, settle)
    local decel = measureDeceleration(-0.5, state.estimate.speed, legTime * 2)
    if decel and decel > 0 then model.decel = decel end
  else
    -- No reverse: the two are the same thing, and guidance uses coastDecel
    -- anyway. Keeping them consistent stops a stale default from making the
    -- ship think it can stop harder than it can.
    model.decel = model.coastDecel
  end

  -- Yaw: turn while under way, because a pivot in place produces no motion
  -- for the estimator to read a heading from.
  nav.allStop()
  sleep(opts.restTime or 4)
  local yawDirection = caps.yawRight and 1 or -1
  local _, yawSamples = sampleSpeedUnder(
    {throttle = nav.TURN_THROTTLE, yaw = yawDirection}, legTime * 1.5, settle)
  local absRates = {}
  for _, r in ipairs(yawSamples) do
    if math.abs(r) > 0 then absRates[#absRates + 1] = math.abs(r) end
  end
  local yawRate = mean(absRates)
  if yawRate and yawRate > 0 then model.yawRate = yawRate end

  -- Climb rate, only if there's powered vertical movement to measure.
  if caps.vertical then
    nav.allStop()
    sleep(opts.restTime or 4)
    local liftDirection = caps.climb and 1 or -1
    local liftSamples = sampleSpeedUnder({lift = liftDirection}, legTime, settle)
    local vys = {}
    for _, s in ipairs(liftSamples) do vys[#vys + 1] = math.abs(s.vy) end
    local liftSpeed = mean(vys)
    if liftSpeed and liftSpeed > 0 then model.liftSpeed = liftSpeed end
  end

  nav.allStop()
  nav.setModel(model)
  return nav.getModel()
end

function nav.calibrate(opts)
  -- Calibration deliberately holds full throttle through several sleeps, which
  -- is the worst possible moment for a bare Ctrl+T: it would leave the ship at
  -- maximum thrust in a turn with the program gone.
  return nav.withSafeShutdown(calibrationRun, opts)
end

function nav.saveModel(path)
  local f = assert(fs.open(path, "w"), "nav.saveModel: could not open " .. path)
  f.write(textutils.serialize(state.model))
  f.close()
end

function nav.loadModel(path)
  if not fs.exists(path) then return false, "not_found" end
  local f = assert(fs.open(path, "r"), "nav.loadModel: could not open " .. path)
  local ok, data = pcall(textutils.unserialize, f.readAll())
  f.close()
  if not ok or type(data) ~= "table" then return false, "corrupt" end
  nav.setModel(data)
  return true
end

-- ===========================================================================
-- Remote autopilot over sip.
--
-- sip already authenticates the sender (its ID can't be spoofed and the
-- payload is encrypted to our key with replay rejection), so authorization
-- here is just "is this ID on the list" - there is no separate password to
-- steal. An unauthorized sender gets a refusal, not silence, so a legitimate
-- operator who forgot to be added can tell the difference from a dead ship.
-- ===========================================================================

function nav.authorizeOperator(id) state.authorizedOperators[id] = true end
function nav.revokeOperator(id) state.authorizedOperators[id] = nil end
function nav.listOperators()
  local ids = {}
  for id in pairs(state.authorizedOperators) do ids[#ids + 1] = id end
  return ids
end

-- Pure command interpreter: decides what a message means without touching
-- the network, so the authorization and validation rules are testable.
-- Returns a reply table, and an action table for the flight loop to enact.
function nav.interpretCommand(senderId, message, authorized)
  if not authorized[senderId] then
    return {ok = false, err = "unauthorized"}, nil
  end
  local request = type(message) == "string" and textutils.unserialize(message) or message
  if type(request) ~= "table" or type(request.cmd) ~= "string" then
    return {ok = false, err = "malformed"}, nil
  end

  local cmd = request.cmd:upper()
  if cmd == "GOTO" then
    if type(request.x) ~= "number" or type(request.y) ~= "number" or type(request.z) ~= "number" then
      return {ok = false, err = "bad_coordinates"}, nil
    end
    local target = {x = request.x, y = request.y, z = request.z}
    return {ok = true, accepted = "GOTO", target = target}, {type = "goto", target = target}
  elseif cmd == "STOP" then
    return {ok = true, accepted = "STOP"}, {type = "stop"}
  elseif cmd == "STATUS" then
    return {ok = true, accepted = "STATUS", state = nav.getState(), model = nav.getModel(),
      capabilities = nav.capabilities()}, nil
  end
  return {ok = false, err = "unknown_command"}, nil
end

local function serveRemoteLoop(opts)
  opts = opts or {}
  local pending = nil    -- target requested but not yet picked up by the flight loop
  local cancelFlag = false

  -- (There used to be a `running` flag guarding both loops here, cleared after
  -- waitForAny returned. It could never do anything: waitForAny only returns
  -- once one of its functions has finished, and at that point the others are
  -- already abandoned coroutines that will never be resumed to re-test it.)

  local function commandLoop()
    while true do
      local senderId, message = sip.receive()
      if senderId then
        local reply, action = nav.interpretCommand(senderId, message, state.authorizedOperators)
        if action then
          if action.type == "goto" then
            pending, cancelFlag = action.target, true -- cancel any current leg, then take the new one
          elseif action.type == "stop" then
            pending, cancelFlag = nil, true
          end
        end
        -- Replying needs the operator's public key, which the handshake loop
        -- below learns; skip the reply rather than error if we don't have it.
        if sip.getPeerPublicKey(senderId) then
          pcall(sip.send, senderId, textutils.serialize(reply))
        end
      end
    end
  end

  local function flightLoop()
    while true do
      local target = pending
      if target then
        pending = nil
        cancelFlag = false
        local ok, err = nav.flyTo(target, {
          shouldAbort = function() return cancelFlag end,
          timeout = opts.legTimeout,
          onTick = opts.onTick
        })
        state.lastError = ok and nil or err
        if opts.onMissionEnd then opts.onMissionEnd(ok, err, target) end
      else
        -- Idle: keep the estimator warm so the next GOTO starts from a
        -- current position and a known heading instead of cold.
        stepEstimator()
        sleep(0.5)
      end
    end
  end

  -- Ctrl+T is delivered to whichever of these happens to be blocked on a pull,
  -- and it bypasses event filters, so without this it would surface as a
  -- "Terminated" error thrown through the middle of the flight loop. parallel
  -- resumes its coroutines in order, so watching for terminate first turns it
  -- into an ordinary return from waitForAny; nav.withSafeShutdown then cuts the
  -- controls. (That wrapper also covers the error route, in case a future
  -- reordering loses this race.)
  local function terminateWatcher() os.pullEventRaw("terminate") end

  parallel.waitForAny(terminateWatcher, sip.listenForHandshakes, commandLoop, flightLoop)
end

-- Blocks forever: listens for operator commands and flies whatever mission
-- is current. Run this as the ship's main program. Returns with the controls
-- cut, whether it ended on Ctrl+T or on an error.
function nav.serveRemote(opts)
  return nav.withSafeShutdown(serveRemoteLoop, opts)
end

-- Operator-side helper: hand a command to a ship and wait for its reply.
-- Returns the reply table, or nil, err.
function nav.sendCommand(shipId, command, timeout)
  timeout = timeout or 10
  if not sip.getPeerPublicKey(shipId) then
    local key = sip.requestIdentity(shipId, timeout)
    if not key then return nil, "no_handshake" end
  end
  sip.send(shipId, textutils.serialize(command))

  local deadline = os.clock() + timeout
  while true do
    local remaining = deadline - os.clock()
    if remaining <= 0 then return nil, "timeout" end
    local senderId, message = sip.receive(remaining)
    if senderId == shipId then
      local ok, reply = pcall(textutils.unserialize, message)
      if ok and type(reply) == "table" then return reply end
    end
  end
end

-- ===========================================================================
-- Self-test: estimator, guidance and model math. No modem/GPS/ship needed.
-- ===========================================================================

function nav.selfTest()
  local allPassed = true
  local function check(name, ok)
    ok = not not ok
    print((ok and "PASS " or "FAIL ") .. name)
    allPassed = allPassed and ok
  end

  check("angle wrap", normalizeAngle(190) == -170 and normalizeAngle(-190) == 170 and
    normalizeAngle(180) == 180 and normalizeAngle(0) == 0)

  -- Minecraft yaw: 0 = +Z south, 90 = -X west, 180 = -Z north, -90 = +X east.
  check("heading from velocity",
    math.abs(headingFromVelocity(0, 1) - 0) < 0.01 and
    math.abs(headingFromVelocity(-1, 0) - 90) < 0.01 and
    math.abs(math.abs(headingFromVelocity(0, -1)) - 180) < 0.01 and
    math.abs(headingFromVelocity(1, 0) + 90) < 0.01)

  check("bearing to target",
    math.abs(bearingTo({x = 0, y = 0, z = 0}, {x = 0, y = 0, z = 10}) - 0) < 0.01 and
    math.abs(bearingTo({x = 0, y = 0, z = 0}, {x = -10, y = 0, z = 0}) - 90) < 0.01)

  check("horizontal distance ignores altitude",
    math.abs(horizontalDistance({x = 0, y = 0, z = 0}, {x = 3, y = 100, z = 4}) - 5) < 0.01)

  -- v^2/2a = 100/4 = 25, plus one second of travel at 10 b/s.
  check("braking distance", math.abs(brakingDistance(10, 2, 1) - 35) < 0.01)
  check("braking distance grows with speed",
    brakingDistance(20, 2, 0) > brakingDistance(10, 2, 0))

  -- Dead reckoning: 2 seconds at 5 b/s along +Z, turning 10 deg/s.
  local e = freshEstimate()
  e.pos = {x = 0, y = 64, z = 0}
  e.vel = {x = 0, y = 0, z = 5}
  e.heading, e.yawRate, e.lastPredictTime = 0, 10, 100
  predict(e, 102)
  check("dead reckoning advances position and heading",
    math.abs(e.pos.z - 10) < 0.01 and math.abs(e.pos.x) < 0.01 and
    math.abs(e.heading - 20) < 0.01)

  -- Fix fusion: two fixes 2s apart, 20 blocks along -X, should read 10 b/s west.
  local f = freshEstimate()
  fuseFix(f, {x = 0, y = 64, z = 0}, 100, 1.0)
  check("first fix sets position without inventing motion",
    f.pos.x == 0 and f.speed == 0 and f.fixCount == 1)
  fuseFix(f, {x = -20, y = 64, z = 0}, 102, 1.0)
  check("second fix derives speed and heading",
    math.abs(f.speed - 10) < 0.01 and f.headingKnown and
    math.abs(f.heading - 90) < 0.01 and f.fixCount == 2)

  -- A crawl below the heading threshold must not overwrite a known heading.
  local slow = freshEstimate()
  fuseFix(slow, {x = 0, y = 64, z = 0}, 100, 1.0)
  fuseFix(slow, {x = 0, y = 64, z = 20}, 102, 1.0) -- heading 0, moving fast
  local headingBefore = slow.heading
  fuseFix(slow, {x = 0.01, y = 64, z = 20.01}, 104, 1.0) -- barely moving
  check("slow drift does not redefine heading",
    slow.headingKnown and math.abs(slow.heading - headingBefore) < 0.01)

  -- coastDecel is deliberately much weaker than decel, as drag-only braking
  -- really is, so the no-reverse cases below have something to bite on.
  local model = {maxSpeed = 8, accel = 2, decel = 2, coastDecel = 0.5,
    yawRate = 20, liftSpeed = 3}

  -- Pointing north (180) but the target is due south (0): must steer, and
  -- keep only turn throttle rather than charging off in the wrong direction.
  local turnState = {pos = {x = 0, y = 64, z = 0}, speed = 1, heading = 180,
    headingKnown = true, yawRate = 0, vel = {x = 0, y = 0, z = 0}}
  local turnCmd = nav.guidanceCommand(turnState, {x = 0, y = 64, z = 200}, model)
  check("turns toward target instead of cruising",
    turnCmd.phase == "turning" and turnCmd.throttle == nav.TURN_THROTTLE and
    math.abs(turnCmd.yaw) > 0)

  -- Aligned and far away: cruise at full throttle.
  local cruiseState = {pos = {x = 0, y = 64, z = 0}, speed = 4, heading = 0,
    headingKnown = true, yawRate = 0, vel = {x = 0, y = 0, z = 4}}
  local cruiseCmd = nav.guidanceCommand(cruiseState, {x = 0, y = 64, z = 200}, model)
  check("cruises when aligned and clear", cruiseCmd.phase == "cruising" and cruiseCmd.throttle == 1)

  -- Fast and nearly on top of the target: brake.
  local brakeState = {pos = {x = 0, y = 64, z = 0}, speed = 10, heading = 0,
    headingKnown = true, yawRate = 0, vel = {x = 0, y = 0, z = 10}}
  local brakeCmd = nav.guidanceCommand(brakeState, {x = 0, y = 64, z = 20}, model)
  check("brakes when inside stopping distance",
    brakeCmd.phase == "braking" and brakeCmd.throttle < 0)

  -- There, and slow: arrived.
  local arrivedState = {pos = {x = 0, y = 64, z = 199}, speed = 0.2, heading = 0,
    headingKnown = true, yawRate = 0, vel = {x = 0, y = 0, z = 0.2}}
  local arrivedCmd = nav.guidanceCommand(arrivedState, {x = 0, y = 64, z = 200}, model)
  check("reports arrival and cuts all controls",
    arrivedCmd.arrived and arrivedCmd.throttle == 0 and arrivedCmd.lift == 0)

  -- Below the target: climb, independent of horizontal work.
  local lowState = {pos = {x = 0, y = 40, z = 0}, speed = 0, heading = 0,
    headingKnown = true, yawRate = 0, vel = {x = 0, y = 0, z = 0}}
  local lowCmd = nav.guidanceCommand(lowState, {x = 0, y = 80, z = 0}, model)
  check("climbs toward target altitude", lowCmd.lift > 0)
  local highCmd = nav.guidanceCommand(
    {pos = {x = 0, y = 120, z = 0}, speed = 0, heading = 0, headingKnown = true,
     yawRate = 0, vel = {x = 0, y = 0, z = 0}}, {x = 0, y = 80, z = 0}, model)
  check("descends toward target altitude", highCmd.lift < 0)

  -- No heading yet: creep to make motion, don't steer blind.
  local blindState = {pos = {x = 0, y = 64, z = 0}, speed = 0, heading = 0,
    headingKnown = false, yawRate = 0, vel = {x = 0, y = 0, z = 0}}
  local blindCmd = nav.guidanceCommand(blindState, {x = 0, y = 64, z = 200}, model)
  check("seeks heading before steering",
    blindCmd.phase == "seeking_heading" and blindCmd.yaw == 0 and blindCmd.throttle > 0)

  local noFixCmd = nav.guidanceCommand({pos = nil, speed = 0, heading = 0,
    headingKnown = false, yawRate = 0, vel = {x = 0, y = 0, z = 0}}, {x = 0, y = 0, z = 0}, model)
  check("refuses to command without a position",
    noFixCmd.phase == "no_position" and noFixCmd.throttle == 0)

  -- ---- Ships that aren't fully equipped -------------------------------
  local fullCaps = {forward = true, reverse = true, yawLeft = true, yawRight = true,
    climb = true, descend = true, vertical = true}
  local noReverse = {forward = true, reverse = false, yawLeft = true, yawRight = true,
    climb = true, descend = true, vertical = true}
  local noVertical = {forward = true, reverse = true, yawLeft = true, yawRight = true,
    climb = false, descend = false, vertical = false}
  local climbOnly = {forward = true, reverse = true, yawLeft = true, yawRight = true,
    climb = true, descend = false, vertical = true}

  -- Same approach, with and without reverse thrust. A ship that can only coast
  -- must give up thrust sooner, because drag stops it over a longer distance.
  local approach = {pos = {x = 0, y = 64, z = 0}, speed = 10, heading = 0,
    headingKnown = true, yawRate = 0, vel = {x = 0, y = 0, z = 10}}
  local farTarget = {x = 0, y = 64, z = 40}
  local withReverse = nav.guidanceCommand(approach, farTarget, model, {capabilities = fullCaps})
  local withoutReverse = nav.guidanceCommand(approach, farTarget, model, {capabilities = noReverse})
  check("reverse-equipped ship still cruising at this range", withReverse.phase == "cruising")
  check("coast-only ship has already stopped accelerating",
    withoutReverse.phase == "coasting" and withoutReverse.throttle == 0)

  -- And when it does slow down, it must never command reverse it hasn't got.
  local closeApproach = {pos = {x = 0, y = 64, z = 0}, speed = 10, heading = 0,
    headingKnown = true, yawRate = 0, vel = {x = 0, y = 0, z = 10}}
  local coastCmd = nav.guidanceCommand(closeApproach, {x = 0, y = 64, z = 20}, model,
    {capabilities = noReverse})
  check("coast-only ship never commands reverse thrust", coastCmd.throttle >= 0)

  -- No vertical control: never command lift, and don't refuse to arrive over
  -- an altitude difference that can't be flown out.
  local wrongAltitude = {pos = {x = 0, y = 30, z = 199}, speed = 0.2, heading = 0,
    headingKnown = true, yawRate = 0, vel = {x = 0, y = 0, z = 0.2}}
  local noVertCmd = nav.guidanceCommand(wrongAltitude, {x = 0, y = 90, z = 200}, model,
    {capabilities = noVertical})
  check("ship without vertical control arrives despite altitude gap",
    noVertCmd.arrived and noVertCmd.lift == 0)

  local vertCmd = nav.guidanceCommand(wrongAltitude, {x = 0, y = 90, z = 200}, model,
    {capabilities = fullCaps})
  check("ship with vertical control holds station to climb",
    (not vertCmd.arrived) and vertCmd.phase == "station_keeping" and vertCmd.lift > 0)

  -- Climb-only ship: can rise to meet a target above, but must not pretend it
  -- can sink to one below.
  local aboveTarget = {pos = {x = 0, y = 120, z = 199}, speed = 0.2, heading = 0,
    headingKnown = true, yawRate = 0, vel = {x = 0, y = 0, z = 0.2}}
  local sinkCmd = nav.guidanceCommand(aboveTarget, {x = 0, y = 80, z = 200}, model,
    {capabilities = climbOnly})
  check("climb-only ship arrives rather than trying to descend",
    sinkCmd.arrived and sinkCmd.lift == 0)
  local riseCmd = nav.guidanceCommand(
    {pos = {x = 0, y = 40, z = 199}, speed = 0.2, heading = 0, headingKnown = true,
     yawRate = 0, vel = {x = 0, y = 0, z = 0.2}}, {x = 0, y = 80, z = 200}, model,
    {capabilities = climbOnly})
  check("climb-only ship still climbs when the target is above",
    riseCmd.lift > 0 and not riseCmd.arrived)

  -- ---- Stepped yaw (helicopter tail) ----------------------------------
  local maxSteps, hyst = 2, 0.25

  -- Small errors leave the tail alone; the boundary needs clearing by the
  -- hysteresis margin. desired = yaw*2, so a step needs desired > 0.75.
  check("small yaw command leaves the tail centred",
    targetDeflectionFor(0.3, 0, maxSteps, hyst) == 0)
  check("clear yaw command steps the tail",
    targetDeflectionFor(0.5, 0, maxSteps, hyst) == 1)

  -- One step per call, never a jump straight to full deflection.
  check("steps one notch at a time, not straight to the stop",
    targetDeflectionFor(1, 0, maxSteps, hyst) == 1 and
    targetDeflectionFor(1, 1, maxSteps, hyst) == 2)

  check("never drives past maximum deflection",
    targetDeflectionFor(1, 2, maxSteps, hyst) == 2 and
    targetDeflectionFor(-1, -2, maxSteps, hyst) == -2)

  check("steps back the other way for an opposite command",
    targetDeflectionFor(-1, 2, maxSteps, hyst) == 1 and
    targetDeflectionFor(-1, 0, maxSteps, hyst) == -1)

  -- Zero yaw must actively unwind the tail, not leave it where it is.
  check("neutral command recentres a deflected tail",
    targetDeflectionFor(0, 2, maxSteps, hyst) == 1 and
    targetDeflectionFor(0, 1, maxSteps, hyst) == 0 and
    targetDeflectionFor(0, -1, maxSteps, hyst) == 0)

  -- Hysteresis: holding one step, a command that merely wobbles around the
  -- boundary must not pull the tail back and forth.
  check("hysteresis holds a step against a wobbling command",
    targetDeflectionFor(0.5, 1, maxSteps, hyst) == 1 and
    targetDeflectionFor(0.4, 1, maxSteps, hyst) == 1 and
    targetDeflectionFor(0.6, 1, maxSteps, hyst) == 1)
  check("but a genuinely reduced command still unwinds",
    targetDeflectionFor(0.1, 1, maxSteps, hyst) == 0)

  -- Capability clamping applied directly.
  local ct, cy, cl = clampToCapabilities(-1, 0, 1, noReverse)
  check("clamp drops reverse on a forward-only drive", ct == 0 and cl == 1)
  local _, _, cl2 = clampToCapabilities(1, 0, -1, climbOnly)
  check("clamp drops descent on a climb-only ship", cl2 == 0)
  local ct3, cy3, cl3 = clampToCapabilities(1, 1, 1, fullCaps)
  check("clamp leaves a fully equipped ship alone", ct3 == 1 and cy3 == 1 and cl3 == 1)

  -- Axis splitting: never drive both directions of an axis at once.
  local fwd = axisOutputs(1, "forward", "reverse")
  local rev = axisOutputs(-0.5, "forward", "reverse")
  local zero = axisOutputs(0, "forward", "reverse")
  check("axis outputs are exclusive and scaled",
    fwd.forward == 15 and fwd.reverse == 0 and
    rev.reverse == 8 and rev.forward == 0 and
    zero.forward == 0 and zero.reverse == 0)

  -- Learning: only after the command has been held, and only toward truth.
  local m = {maxSpeed = 8, accel = 2, decel = 2, yawRate = 20, liftSpeed = 3}
  learnFromObservation(m, {speed = 12, headingKnown = true, yawRate = 0,
    vel = {x = 0, y = 0, z = 12}}, {throttle = 1, yaw = 0, lift = 0}, 0.5, 0.2)
  check("ignores observations under a fresh command", m.maxSpeed == 8)
  learnFromObservation(m, {speed = 12, headingKnown = true, yawRate = 0,
    vel = {x = 0, y = 0, z = 12}}, {throttle = 1, yaw = 0, lift = 0}, 5, 0.2)
  check("learns top speed toward observed value", m.maxSpeed > 8 and m.maxSpeed < 12)
  learnFromObservation(m, {speed = 5, headingKnown = true, yawRate = 30,
    vel = {x = 0, y = 0, z = 5}}, {throttle = 0, yaw = 1, lift = 0}, 5, 0.2)
  check("learns yaw rate toward observed value", m.yawRate > 20 and m.yawRate < 30)

  -- Authorization and validation of remote commands.
  local authorized = {[7] = true}
  local reply1 = nav.interpretCommand(9, {cmd = "GOTO", x = 1, y = 2, z = 3}, authorized)
  check("rejects unauthorized operator", reply1.ok == false and reply1.err == "unauthorized")

  local reply2, action2 = nav.interpretCommand(7, {cmd = "GOTO", x = 1, y = 2, z = 3}, authorized)
  check("accepts authorized GOTO",
    reply2.ok and action2 and action2.type == "goto" and action2.target.x == 1)

  local reply3 = nav.interpretCommand(7, {cmd = "GOTO", x = "over there"}, authorized)
  check("rejects bad coordinates", reply3.ok == false and reply3.err == "bad_coordinates")

  local reply4, action4 = nav.interpretCommand(7, {cmd = "STOP"}, authorized)
  check("accepts STOP", reply4.ok and action4 and action4.type == "stop")

  local reply5 = nav.interpretCommand(7, {cmd = "SELF_DESTRUCT"}, authorized)
  check("rejects unknown command", reply5.ok == false and reply5.err == "unknown_command")

  local reply6 = nav.interpretCommand(7, "not a table", authorized)
  check("rejects malformed message", reply6.ok == false and reply6.err == "malformed")

  -- Serialized GOTO, the form that actually arrives over sip.
  local reply7, action7 = nav.interpretCommand(7,
    textutils.serialize({cmd = "GOTO", x = 5, y = 6, z = 7}), authorized)
  check("accepts serialized GOTO over the wire",
    reply7.ok and action7 and action7.target.z == 7)

  -- ---- Shutdown safety -------------------------------------------------
  -- The outputs drive real thrust, so every way out of a blocking call has to
  -- reach allStop. Ctrl+T is the one that used to escape: it arrives as
  -- error("Terminated", 0) from whatever pull was blocking. Drive that path
  -- here with a stand-in allStop, so the test counts the cleanup instead of
  -- toggling redstone.
  local realAllStop = nav.allStop
  local stops = 0
  nav.allStop = function() stops = stops + 1 end

  local normalOk, valueA, valueB =
    pcall(nav.withSafeShutdown, function() return "a", "b" end)
  check("safe shutdown stops the ship on a normal return, passing results through",
    normalOk and stops == 1 and valueA == "a" and valueB == "b")

  local termOk, termErr = pcall(nav.withSafeShutdown, function()
    error("Terminated", 0) -- exactly what os.pullEvent raises on Ctrl+T
  end)
  check("terminate cuts the controls", stops == 2)
  -- Re-raised, not swallowed: a program that ignored Ctrl+T would be unkillable.
  check("terminate still kills the program", termOk == false and termErr == "Terminated")

  local bugOk, bugErr = pcall(nav.withSafeShutdown, function() error("boom", 0) end)
  check("an error in flight also cuts the controls, and still reports itself",
    stops == 3 and bugOk == false and tostring(bugErr):find("boom") ~= nil)

  -- Arguments reach the wrapped body, since serveRemote/calibrate/flyTo pass
  -- theirs through it.
  local gotArg
  pcall(nav.withSafeShutdown, function(a, b) gotArg = a + b end, 40, 2)
  check("safe shutdown forwards arguments to the wrapped call", gotArg == 42)

  nav.allStop = realAllStop

  -- sgps.locate raises rather than returning nil, err for some failures (no
  -- modem open, too few trusted hosts). That must degrade into "no fix", which
  -- the autopilot already knows how to stop for - not an exception unwinding
  -- the flight loop with the throttle still up.
  local realLocate, savedLastError = sgps.locate, state.lastError
  sgps.locate = function() error("sgps: simulated blow-up", 0) end
  local fixOk, fixErr = nav.fix()
  check("a locate that raises becomes a failed fix, not an exception",
    fixOk == false and tostring(fixErr):find("simulated blow%-up") ~= nil)
  check("and the real reason is kept for telemetry",
    tostring(state.lastError):find("simulated blow%-up") ~= nil)
  sgps.locate = realLocate
  state.lastError = savedLastError

  -- Capability caching must not change what capabilities() reports, and must
  -- notice a rewiring.
  local savedMap = state.controlMap
  local capsA = nav.capabilities()
  check("capability cache returns a stable answer", nav.capabilities() == capsA)
  nav.setControlMap(nav.CONTROL_MAP_MINIMAL)
  local capsB = nav.capabilities()
  check("capability cache is invalidated by a new control map",
    capsB ~= capsA and capsB.forward == true and capsB.reverse == false and
    capsB.vertical == false and capsB.yawMode == "level")
  nav.setControlMap(savedMap)
  local capsC = nav.capabilities()
  check("capabilities follow the wiring back",
    capsC.reverse == (savedMap.reverse ~= nil) and
    capsC.vertical == ((savedMap.up ~= nil) or (savedMap.down ~= nil)))

  print(allPassed and "SELF TEST PASSED" or "SELF TEST FAILED")
  return allPassed
end

nav.WIRING = [[
sNav wiring - Create Redstone Links
===================================
One transmitter link per computer side, each on its own frequency, paired
with a receiver link at the machinery it drives.

  front  -> forward thrust      back   -> reverse thrust   (optional)
  left   -> yaw left (port)     right  -> yaw right (starboard)
  top    -> climb    (optional) bottom -> descend          (optional)

Only `forward` and one yaw control are required. Wire what your ship has
and omit the rest from the control map - the autopilot checks
nav.capabilities() and plans around what's missing (a ship with no reverse
coasts to a stop from further out; a ship with no lift ignores target
altitude). Presets: nav.CONTROL_MAP_NO_VERTICAL, nav.CONTROL_MAP_NO_REVERSE,
nav.CONTROL_MAP_MINIMAL.

STEPPED TAIL (helicopters) - nav.CONTROL_MAP_STEPPED_YAW replaces the two
yaw lines with:

  left  -> yawStep       one pulse = one step of the tail
  right -> yawDirection  powered = step toward starboard

  power -> Gearshift ------> Sequenced Gearshift ------> tail shaft
              ^                      ^
        yawDirection link        yawStep link

Program the Sequenced Gearshift with a single instruction, "Turn by Angle:
22" (match nav.YAW_STEP_ANGLE), then End - so one pulse is one step. The
Gearshift reverses the incoming rotation so the same instruction steps the
other way; verify in-game that it does, or use two Sequenced Gearshifts
with opposite angles instead.

Centre the tail physically before starting, then call
nav.assumeYawCentered() - there is no position feedback, so the software
trusts that claim for every move afterwards.

"front" is the side the screen faces. Sides are relative to the COMPUTER;
the link frequencies decide which machinery each one reaches.

For each control:
  1. Place a Redstone Link touching that side of the computer, mode
     TRANSMIT (the default; a wrench toggles it).
  2. Set its two frequency slots to a pair of items unique to that
     control. Reusing a pair makes one output drive several systems.
  3. On the ship, place a Redstone Link with the SAME two items, mode
     RECEIVE, so its output feeds that control's machinery.
  4. Include both links in the assembled contraption if they move with
     the ship. A link left behind stops matching the one that flew off.

Signals are analog 0-15, so throttle level travels with them. Feed them
into a Rotational Speed Controller, an Analog Lever slot, a Sequenced
Gearshift, or a comparator gate. On/off machinery reads any nonzero level
as on and simply ignores the extra resolution.

More than six controls? Give a control a `color` field instead of a plain
side, e.g. {side = "back", color = colors.red}, and it goes out as bundled
cable - sixteen per side, but on/off only, no throttle levels.
]]

local progArgs = {...}
if progArgs[1] == "test" then
  nav.selfTest()
elseif progArgs[1] == "wiring" then
  print(nav.WIRING)
end

return nav
