--[[
  enc.lua - basic public/private key encryption utility for ComputerCraft

  Implements RSA key generation (from scratch, using a small arbitrary
  precision integer library) for key exchange, combined with an RC4
  stream cipher for the actual message body (hybrid encryption, the same
  pattern real protocols like TLS use with RSA+AES).

  SECURITY NOTE: this is a "basic" / educational implementation intended
  for lightweight obfuscation between turtles/computers, not a hardened
  cryptosystem. ComputerCraft has no cryptographically secure random
  source, RC4 is a weak cipher by modern standards, and key sizes here
  are limited by how slow pure-Lua bignum math is. Don't use this to
  protect anything that actually matters.

  Usage:
    local enc = require("enc")  -- or: local enc = dofile("enc.lua")

    local pub, priv = enc.generateKeyPair(256) -- bits, default 256, min 192

    local package = enc.encrypt(pub, "hello world")
    local message = enc.decrypt(priv, package)

    -- keys/packages are plain tables of hex strings, easy to save/send:
    local str = enc.serialize(pub)
    local pub2 = enc.deserialize(str)

  Run `enc.lua test` from the shell to generate a key pair and round-trip
  a test message; `enc.lua bench` times the primitives.

  ---------------------------------------------------------------------
  WHY THIS IS AS FAST AS IT IS

  Everything above this file (sip -> sGps -> sNav) pays for RSA on every
  message, and a position fix costs several RSA operations, so the modular
  arithmetic here sets the pace for the whole stack. Three things carry
  nearly all of that:

    * Modular multiplication uses MONTGOMERY reduction, not divide-and-
      take-the-remainder. A modexp is thousands of `a*b mod m` steps; doing
      each one with long division costs O(bits) big-number subtract/compare
      passes, while Montgomery's REDC costs one extra multiply-accumulate
      sweep, so the reduction stops being the dominant term. This is the
      single biggest win in the file.

    * Where a real division IS needed (setup, gcd, hex conversion) it's
      Knuth algorithm D in base 2^24 - O(limbs^2) - instead of the old
      bit-by-bit restoring loop, which was O(bits x limbs) and allocated a
      fresh table per bit.

    * Private-key operations use the CHINESE REMAINDER THEOREM: two
      exponentiations modulo the half-size primes instead of one modulo n.
      Half the modulus and half the exponent each, so about a quarter of
      the work. `d` is still stored, so keys written by older versions
      (which have no p/q) keep working via the slow path.

  Base 2^24 limbs are chosen so that a limb maps to exactly 6 hex digits
  AND the worst intermediate in the Montgomery inner loop,
  (2^24-1)^2 + 2(2^24-1) = 2^48 - 1, stays inside the 2^53 exact-integer
  range of Lua's doubles. Every accumulator below is bounded with that in
  mind; changing BASE without redoing that arithmetic will silently corrupt
  results on large keys.
  ---------------------------------------------------------------------
]]

local enc = {}

math.randomseed((os.epoch and os.epoch("utc")) or os.time())

-- Cache the library functions the hot loops call. In CC's Lua a global
-- lookup is a hash lookup on _ENV every time, and these run millions of
-- times per key generation.
local floor = math.floor
local sformat = string.format
local tconcat = table.concat
local bxor = bit32 and bit32.bxor

-- ===========================================================================
-- CC watchdog helper: pure-Lua bignum math can run long enough to trip
-- ComputerCraft's "too long without yielding" abort (7s of cumulative Lua,
-- then the computer is shut down 1.5s later). Queuing and pulling a private
-- event resets that timer without any real delay.
--
-- The yield is driven by ELAPSED TIME, not by an iteration count, and that
-- matters for correctness as much as for speed: a filtered `os.pullEvent`
-- discards every event that arrives while it waits, so each yield can eat an
-- incoming modem_message. Yielding on a clock means operations that finish
-- well inside the budget - which, with Montgomery + CRT, is every encrypt and
-- decrypt - never yield at all and so never drop anything. Only key
-- generation, which runs alone at first boot, yields in practice.
-- ===========================================================================

enc.YIELD_BUDGET = 2.5 -- seconds of Lua between yields; CC aborts at 7

local YIELD_EVENT = "enc_lua_yield"
local lastYield = nil

local function yieldTick()
  os.queueEvent(YIELD_EVENT)
  os.pullEvent(YIELD_EVENT)
  lastYield = os.clock()
end

-- Yields only if we're getting close to the watchdog limit.
local function maybeYield()
  local now = os.clock()
  if not lastYield then
    lastYield = now
  elseif now - lastYield >= enc.YIELD_BUDGET then
    yieldTick()
  end
end

-- ===========================================================================
-- Bignum: unsigned arbitrary precision integers.
-- Little-endian arrays of base-2^24 limbs. See the note in the file header
-- for why 2^24 and not something else.
-- ===========================================================================

local BASE = 16777216 -- 2^24
local BASE_BITS = 24
local BASE_HALF = 8388608 -- 2^23
local INV_BASE = 1 / BASE -- exact: BASE is a power of two, so x * INV_BASE
                          -- is an exact exponent shift for any integer x
                          -- below 2^53, and multiplying beats dividing

local POW2 = {}
for i = 0, BASE_BITS do POW2[i] = 2 ^ i end

local function trim(a)
  local n = #a
  while n > 1 and a[n] == 0 do
    a[n] = nil
    n = n - 1
  end
  return a
end

-- Significant length without mutating `a`. Several callers pass numbers they
-- still need intact, which the trimming version above quietly breaks.
local function bnLen(a)
  local n = #a
  while n > 1 and a[n] == 0 do n = n - 1 end
  return n
end

local function bnFromInt(x)
  if x == 0 then return {0} end
  local res = {}
  while x > 0 do
    res[#res + 1] = x % BASE
    x = floor(x / BASE)
  end
  return res
end

local function bnCopy(a)
  local res = {}
  for i = 1, #a do res[i] = a[i] end
  return res
end

local function bnCompare(a, b)
  local la, lb = bnLen(a), bnLen(b)
  if la ~= lb then return la < lb and -1 or 1 end
  for i = la, 1, -1 do
    local ai, bi = a[i], b[i]
    if ai ~= bi then return ai < bi and -1 or 1 end
  end
  return 0
end

local function bnAdd(a, b)
  local la, lb = #a, #b
  local n = la > lb and la or lb
  local res = {}
  local carry = 0
  for i = 1, n do
    local v = (a[i] or 0) + (b[i] or 0) + carry
    if v >= BASE then
      res[i] = v - BASE
      carry = 1
    else
      res[i] = v
      carry = 0
    end
  end
  if carry > 0 then res[n + 1] = carry end
  return res
end

-- assumes a >= b
local function bnSub(a, b)
  local res = {}
  local borrow = 0
  for i = 1, #a do
    local v = a[i] - (b[i] or 0) - borrow
    if v < 0 then
      res[i] = v + BASE
      borrow = 1
    else
      res[i] = v
      borrow = 0
    end
  end
  return trim(res)
end

local function bnSubOne(a) return bnSub(a, {1}) end

-- Adds a small non-negative integer (< BASE) in place.
local function bnAddSmallInPlace(a, k)
  local i = 1
  local carry = k
  while carry > 0 do
    local v = (a[i] or 0) + carry
    if v >= BASE then
      a[i] = v - BASE
      carry = 1
    else
      a[i] = v
      carry = 0
    end
    i = i + 1
  end
  return a
end

local function bnMul(a, b)
  local la, lb = bnLen(a), bnLen(b)
  local res = {}
  for i = 1, la + lb do res[i] = 0 end
  for i = 1, la do
    local ai = a[i]
    if ai ~= 0 then
      local carry = 0
      local base = i - 1
      for j = 1, lb do
        local k = base + j
        local v = res[k] + ai * b[j] + carry
        carry = floor(v * INV_BASE)
        res[k] = v - carry * BASE
      end
      local k = base + lb + 1
      while carry > 0 do
        local v = res[k] + carry
        carry = floor(v * INV_BASE)
        res[k] = v - carry * BASE
        k = k + 1
      end
    end
  end
  return trim(res)
end

local function bnIsZero(a) return bnLen(a) == 1 and a[1] == 0 end
local function bnIsOne(a) return bnLen(a) == 1 and a[1] == 1 end
local function bnIsEven(a) return a[1] % 2 == 0 end

local function bnBitLength(a)
  local n = bnLen(a)
  local top = a[n]
  if n == 1 and top == 0 then return 0 end
  local bits = (n - 1) * BASE_BITS
  while top > 0 do
    bits = bits + 1
    top = floor(top / 2)
  end
  return bits
end

local function bnTestBit(a, i)
  local limb = a[floor(i / BASE_BITS) + 1]
  if not limb then return false end
  return floor(limb / POW2[i % BASE_BITS]) % 2 == 1
end

local function bnShiftRight1(a)
  local res = {}
  local carry = 0
  for i = #a, 1, -1 do
    local v = a[i] + carry * BASE
    local half = floor(v / 2)
    res[i] = half
    carry = v - half * 2
  end
  return trim(res)
end

-- Shifts left by k bits, 0 <= k < BASE_BITS. a[i] * 2^k <= (2^24-1)*2^23,
-- comfortably inside 2^53.
local function bnShiftLeftBits(a, k)
  if k == 0 then return bnCopy(a) end
  local mul = POW2[k]
  local res = {}
  local carry = 0
  local n = #a
  for i = 1, n do
    local v = a[i] * mul + carry
    carry = floor(v * INV_BASE)
    res[i] = v - carry * BASE
  end
  if carry > 0 then res[n + 1] = carry end
  return res
end

local function bnShiftRightBits(a, k)
  if k == 0 then return a end
  local div = POW2[k]
  local res = {}
  local carry = 0
  for i = #a, 1, -1 do
    local v = carry * BASE + a[i]
    local q = floor(v / div)
    res[i] = q
    carry = v - q * div
  end
  return trim(res)
end

-- ---------------------------------------------------------------------------
-- Knuth algorithm D long division, base 2^24.
--
-- Replaces a bit-by-bit restoring loop that ran O(bits(a)) iterations, each
-- allocating tables for a shift, a compare and a subtract. This is O(limbs^2)
-- with no allocation in the inner loop. Returns quotient, remainder.
-- ---------------------------------------------------------------------------
local function bnDivMod(a, b)
  local vn = bnLen(b)

  -- Single-limb divisor: the estimate is exact, so skip the whole apparatus.
  if vn == 1 then
    local d = b[1]
    if d == 0 then error("enc: division by zero", 2) end
    local an = bnLen(a)
    local q = {}
    local rem = 0
    for i = an, 1, -1 do
      local cur = rem * BASE + a[i] -- rem < d <= 2^24-1, so cur < 2^48
      local qi = floor(cur / d)
      q[i] = qi
      rem = cur - qi * d
    end
    return trim(q), {rem}
  end

  if bnCompare(a, b) < 0 then return {0}, bnCopy(a) end

  -- Normalise so the divisor's top limb is >= BASE/2. That is what bounds the
  -- error of the two-limb quotient estimate below to at most one.
  local shift = 0
  local top = b[vn]
  while top < BASE_HALF do
    top = top * 2
    shift = shift + 1
  end

  local v = bnShiftLeftBits(b, shift)
  local shifted = bnShiftLeftBits(a, shift)
  local un = bnLen(shifted)
  -- Algorithm D wants exactly un+1 limbs of dividend, with a known-zero top.
  local u = {}
  for i = 1, un do u[i] = shifted[i] end
  u[un + 1] = 0

  local vtop, vsec = v[vn], v[vn - 1]
  local m = un - vn
  local q = {}

  for j = m, 0, -1 do
    local num = u[j + vn + 1] * BASE + u[j + vn]
    local qhat = floor(num / vtop)
    local rhat = num - qhat * vtop
    -- num < 2^48 and vtop >= 2^23, so qhat <= 2^25 and qhat*vsec < 2^49.
    while qhat >= BASE or qhat * vsec > rhat * BASE + u[j + vn - 1] do
      qhat = qhat - 1
      rhat = rhat + vtop
      if rhat >= BASE then break end
    end

    -- u[j+1 .. j+vn+1] -= qhat * v
    local borrow, carry = 0, 0
    for i = 1, vn do
      local p = qhat * v[i] + carry
      carry = floor(p * INV_BASE)
      local t = u[j + i] - (p - carry * BASE) - borrow
      if t < 0 then
        u[j + i] = t + BASE
        borrow = 1
      else
        u[j + i] = t
        borrow = 0
      end
    end

    local t = u[j + vn + 1] - carry - borrow
    if t < 0 then
      -- Estimate was one too high (rare): give the divisor back.
      u[j + vn + 1] = t + BASE
      qhat = qhat - 1
      local c = 0
      for i = 1, vn do
        local s = u[j + i] + v[i] + c
        if s >= BASE then
          u[j + i] = s - BASE
          c = 1
        else
          u[j + i] = s
          c = 0
        end
      end
      u[j + vn + 1] = (u[j + vn + 1] + c) % BASE
    else
      u[j + vn + 1] = t
    end
    q[j + 1] = qhat
  end

  local r = {}
  for i = 1, vn do r[i] = u[i] end
  return trim(q), bnShiftRightBits(trim(r), shift)
end

local function bnMod(a, m)
  local _, r = bnDivMod(a, m)
  return r
end

local function bnMulMod(a, b, m)
  local _, r = bnDivMod(bnMul(a, b), m)
  return r
end

local function bnModSmall(a, m)
  local r = 0
  for i = bnLen(a), 1, -1 do
    r = (r * BASE + a[i]) % m -- callers keep m small enough that r*BASE < 2^53
  end
  return r
end

local function bnToHex(a)
  local n = bnLen(a)
  local parts = {}
  parts[1] = sformat("%x", a[n])
  for i = n - 1, 1, -1 do
    parts[#parts + 1] = sformat("%06x", a[i])
  end
  return tconcat(parts)
end

local function bnFromHex(hex)
  hex = hex:gsub("^0[xX]", "")
  if hex == "" then return {0} end
  local pad = (6 - (#hex % 6)) % 6
  if pad > 0 then hex = ("0"):rep(pad) .. hex end
  local res = {}
  local n = #hex
  local nlimbs = n / 6
  for i = 1, nlimbs do
    res[i] = tonumber(hex:sub(n - i * 6 + 1, n - (i - 1) * 6), 16)
  end
  return trim(res)
end

-- ===========================================================================
-- Montgomery arithmetic.
--
-- Working in the Montgomery domain (x -> x*R mod m, R = BASE^n) turns
-- "multiply then reduce mod m" into "multiply-accumulate twice", with no
-- division and no comparison loop. The cost is converting in and out once per
-- exponentiation, which is nothing against hundreds of multiplications.
--
-- Requires an ODD modulus. Every modulus used here is an RSA modulus or one of
-- its prime factors, so that always holds - montSetup asserts it rather than
-- returning quietly wrong answers if that ever changes.
-- ===========================================================================

-- n' such that n0 * n' == -1 (mod 2^24), by Newton iteration on the 2-adic
-- inverse: each step doubles the number of correct bits, so 1 -> 2 -> 4 -> 8
-- -> 16 -> 32 covers 24 bits in five steps.
local function montInverse(n0)
  local x = 1
  for _ = 1, 5 do
    local t = (n0 * x) % BASE          -- < 2^48
    x = (x * ((2 - t) % BASE)) % BASE  -- < 2^48
  end
  return (BASE - x) % BASE
end

local function montSetup(m)
  local n = bnLen(m)
  assert(m[1] % 2 == 1, "enc: Montgomery reduction needs an odd modulus")
  local mm = {}
  for i = 1, n do mm[i] = m[i] end

  -- R^2 mod m, the constant that converts into the Montgomery domain.
  local big = {}
  for i = 1, 2 * n do big[i] = 0 end
  big[2 * n + 1] = 1
  local _, r2 = bnDivMod(big, mm)
  local R2 = {}
  for i = 1, n do R2[i] = r2[i] or 0 end

  return {m = mm, mp = montInverse(mm[1]), n = n, R2 = R2}
end

-- out = a * b * R^-1 mod m. a, b, m, out are exactly n limbs; t is scratch of
-- n+2. `out` must not alias a or b; a and b may be the same table (squaring).
--
-- This is Koc's CIOS: interleave one multiply-accumulate pass with one
-- reduction pass per limb of b. Given a,b < m the running total stays below
-- 2m, so a single conditional subtract at the end lands in [0, m).
local function montMul(a, b, m, mp, n, out, t)
  for i = 1, n + 2 do t[i] = 0 end

  for i = 1, n do
    local bi = b[i]
    local c = 0
    if bi ~= 0 then
      for j = 1, n do
        -- t[j] + a[j]*bi + c <= (B-1) + (B-1)^2 + (B-1) = B^2-1 < 2^48
        local v = t[j] + a[j] * bi + c
        c = floor(v * INV_BASE)
        t[j] = v - c * BASE
      end
    end
    local v = t[n + 1] + c
    c = floor(v * INV_BASE)
    t[n + 1] = v - c * BASE
    t[n + 2] = c

    -- Choose u so the low limb cancels, then shift the whole total down one
    -- limb - that division by BASE is what makes the reduction free.
    local u = (t[1] * mp) % BASE
    local w = t[1] + u * m[1]
    local cc = floor(w * INV_BASE) -- low limb is zero by construction
    for j = 2, n do
      w = t[j] + u * m[j] + cc
      cc = floor(w * INV_BASE)
      t[j - 1] = w - cc * BASE
    end
    w = t[n + 1] + cc
    cc = floor(w * INV_BASE)
    t[n] = w - cc * BASE
    t[n + 1] = t[n + 2] + cc
  end

  -- t < 2m, held in t[1..n+1]; subtract m once if it doesn't already fit.
  local ge = t[n + 1] > 0
  if not ge then
    for i = n, 1, -1 do
      local ti, mi = t[i], m[i]
      if ti ~= mi then
        ge = ti > mi
        break
      end
      if i == 1 then ge = true end
    end
  end
  if ge then
    local borrow = 0
    for i = 1, n do
      local d = t[i] - m[i] - borrow
      if d < 0 then
        out[i] = d + BASE
        borrow = 1
      else
        out[i] = d
        borrow = 0
      end
    end
  else
    for i = 1, n do out[i] = t[i] end
  end
  return out
end

-- Modular exponentiation, left-to-right binary, entirely in the Montgomery
-- domain. `ctx` comes from montSetup and may be reused across calls with the
-- same modulus, which is the point of keeping it separate.
local function bnModPowCtx(base, exp, ctx)
  local n, m, mp, R2 = ctx.n, ctx.m, ctx.mp, ctx.R2

  local nbits = bnBitLength(exp)
  local reduced = base
  if bnCompare(reduced, m) >= 0 then reduced = bnMod(reduced, m) end

  local bp, one = {}, {}
  for i = 1, n do
    bp[i] = reduced[i] or 0
    one[i] = 0
  end
  one[1] = 1

  local t = {}
  local bm, cur, other = {}, {}, {}
  montMul(bp, R2, m, mp, n, bm, t)  -- base in Montgomery form
  montMul(one, R2, m, mp, n, cur, t) -- 1 in Montgomery form

  -- Unpack the exponent's bits once instead of re-deriving each from its limb.
  local bits = {}
  for i = 1, nbits do bits[i] = bnTestBit(exp, i - 1) end

  local sinceYield = 0
  for i = nbits, 1, -1 do
    montMul(cur, cur, m, mp, n, other, t)
    cur, other = other, cur
    if bits[i] then
      montMul(cur, bm, m, mp, n, other, t)
      cur, other = other, cur
    end
    sinceYield = sinceYield + 1
    if sinceYield >= 64 then
      sinceYield = 0
      maybeYield()
    end
  end

  montMul(cur, one, m, mp, n, other, t) -- back out of the Montgomery domain
  return trim(other)
end

local function bnModPow(base, exp, mod)
  return bnModPowCtx(base, exp, montSetup(mod))
end

-- ===========================================================================
-- Signed bignum wrapper, only needed for the extended Euclidean algorithm
-- used to compute the RSA private exponent.
-- ===========================================================================

local function sgnFromMag(mag, sign)
  if bnIsZero(mag) then sign = 1 end
  return {sign = sign, mag = mag}
end

local function sgnSub(x, y)
  local ySign = -y.sign
  if bnIsZero(y.mag) then ySign = 1 end
  local yNeg = {sign = ySign, mag = y.mag}
  if x.sign == yNeg.sign then
    return sgnFromMag(bnAdd(x.mag, yNeg.mag), x.sign)
  end
  local c = bnCompare(x.mag, yNeg.mag)
  if c == 0 then return sgnFromMag({0}, 1) end
  if c > 0 then return sgnFromMag(bnSub(x.mag, yNeg.mag), x.sign) end
  return sgnFromMag(bnSub(yNeg.mag, x.mag), yNeg.sign)
end

local function sgnMulBn(x, b) return sgnFromMag(bnMul(x.mag, b), x.sign) end

-- extended gcd of unsigned bignums a, b: returns gcd, and x such that
-- a*x = gcd (mod b)
local function bnExtGcd(a, b)
  local old_r, r = bnCopy(a), bnCopy(b)
  local old_s, s = sgnFromMag(bnFromInt(1), 1), sgnFromMag(bnFromInt(0), 1)
  while not bnIsZero(r) do
    local q, rem = bnDivMod(old_r, r)
    old_r, r = r, rem
    local newS = sgnSub(old_s, sgnMulBn(s, q))
    old_s, s = s, newS
    maybeYield()
  end
  return old_r, old_s
end

local function bnModInverse(e, phi)
  local g, x = bnExtGcd(e, phi)
  if not bnIsOne(g) then return nil end
  local r = bnMod(x.mag, phi)
  if x.sign < 0 and not bnIsZero(r) then
    return bnSub(phi, r)
  end
  return r
end

-- ===========================================================================
-- Randomness + primality (Miller-Rabin) for RSA key generation.
-- ===========================================================================

local function bnRandomBits(bits)
  local nlimbs = math.ceil(bits / BASE_BITS)
  local res = {}
  for i = 1, nlimbs - 1 do res[i] = math.random(0, BASE - 1) end
  local topBits = bits - (nlimbs - 1) * BASE_BITS
  local half = floor(2 ^ (topBits - 1))
  res[nlimbs] = math.random(0, half > 1 and half - 1 or 0) + half
  return trim(res)
end

-- Odd primes below 1000, sieved at load. The old list stopped at 113; going
-- further is nearly free per candidate and removes far more composites before
-- the expensive Miller-Rabin rounds run. Roughly 12% of odd numbers survive
-- trial division to 1000, against 26% to 113.
local SMALL_PRIMES = {}
do
  local LIMIT = 1000
  local composite = {}
  for i = 3, LIMIT, 2 do
    if not composite[i] then
      SMALL_PRIMES[#SMALL_PRIMES + 1] = i
      for j = i * i, LIMIT, 2 * i do composite[j] = true end
    end
  end
end
local NUM_SMALL_PRIMES = #SMALL_PRIMES

local function millerRabin(n, rounds)
  local nMinus1 = bnSubOne(n)
  local two = bnFromInt(2)
  local d = bnCopy(nMinus1)
  local s = 0
  while bnIsEven(d) do
    d = bnShiftRight1(d)
    s = s + 1
  end

  -- One Montgomery context for the whole test rather than one per modexp.
  local ctx = montSetup(n)
  local nbits = bnBitLength(n)

  for _ = 1, rounds do
    local a
    repeat
      a = bnRandomBits(nbits)
    until bnCompare(a, two) >= 0 and bnCompare(a, nMinus1) < 0
    local x = bnModPowCtx(a, d, ctx)
    if not (bnIsOne(x) or bnCompare(x, nMinus1) == 0) then
      local composite = true
      for _ = 1, s - 1 do
        x = bnMulMod(x, x, n)
        if bnCompare(x, nMinus1) == 0 then
          composite = false
          break
        end
      end
      if composite then return false end
    end
    maybeYield()
  end
  return true
end

-- Draws one random odd candidate and walks upward through odd numbers from
-- there. Walking lets the small-prime residues be advanced by an addition per
-- prime instead of a full multi-limb modulo per prime per candidate, which is
-- what makes a 168-prime sieve cheap enough to be worth running.
local function generateProbablePrime(bits)
  while true do
    local candidate = bnRandomBits(bits)
    if candidate[1] % 2 == 0 then candidate[1] = candidate[1] + 1 end

    local residues = {}
    for i = 1, NUM_SMALL_PRIMES do
      residues[i] = bnModSmall(candidate, SMALL_PRIMES[i])
    end

    for _ = 1, 2048 do
      -- Stepping must not push the candidate into an extra bit, or n would
      -- come out the wrong size; fall back to a fresh draw if it does.
      if bnBitLength(candidate) ~= bits then break end

      local divisible = false
      for i = 1, NUM_SMALL_PRIMES do
        if residues[i] == 0 then
          divisible = true
          break
        end
      end
      if not divisible and millerRabin(candidate, 8) then return candidate end

      bnAddSmallInPlace(candidate, 2)
      for i = 1, NUM_SMALL_PRIMES do
        local p = SMALL_PRIMES[i]
        local r = residues[i] + 2
        if r >= p then r = r - p end
        residues[i] = r
      end
      maybeYield()
    end
  end
end

-- ===========================================================================
-- RSA key generation.
-- ===========================================================================

local E = 65537

function enc.generateKeyPair(bits)
  bits = bits or 256
  assert(type(bits) == "number" and bits % 2 == 0 and bits >= 192,
    "enc.generateKeyPair: bits must be an even number >= 192 (256+ recommended)")

  local half = bits / 2
  local e = bnFromInt(E)
  local p, q, n, d

  while true do
    p = generateProbablePrime(half)
    repeat
      q = generateProbablePrime(half)
    until bnCompare(p, q) ~= 0

    -- Canonicalise p > q. The CRT recombination in enc.decrypt works modulo p
    -- while m2 is only known to be below q, so keeping p the larger factor
    -- means the reduction step there is normally a no-op. (decrypt reduces
    -- defensively anyway, so a key with the other ordering still works.)
    if bnCompare(p, q) < 0 then p, q = q, p end

    n = bnMul(p, q)
    local pMinus1, qMinus1 = bnSubOne(p), bnSubOne(q)
    local phi = bnMul(pMinus1, qMinus1)

    -- E is prime, so gcd(E, phi) is 1 unless E divides phi. One small modulo
    -- answers that; the full Euclidean gcd it replaces was pure overhead.
    if bnModSmall(phi, E) ~= 0 then
      d = bnModInverse(e, phi)
      if d then
        -- Chinese remainder parameters, so decryption can work modulo p and q
        -- separately instead of modulo n. Roughly a 4x saving on every
        -- private-key operation.
        local dp = bnMod(d, pMinus1)
        local dq = bnMod(d, qMinus1)
        local qinv = bnModInverse(q, p)
        if qinv then
          -- p must be the larger factor: the CRT recombination below reduces
          -- modulo p, and (m1 - m2) is only guaranteed to fit if it is.
          local publicKey = {n = bnToHex(n), e = bnToHex(e)}
          local privateKey = {
            n = bnToHex(n), d = bnToHex(d),
            p = bnToHex(p), q = bnToHex(q),
            dp = bnToHex(dp), dq = bnToHex(dq), qinv = bnToHex(qinv)
          }
          return publicKey, privateKey
        end
      end
    end
  end
end

-- ===========================================================================
-- Byte/hex helpers + RC4 stream cipher for the symmetric message body.
-- ===========================================================================

-- Byte <-> hex through lookup tables. These run once per byte of every
-- message, and string.format per byte was showing up in profiles.
local HEX_BYTE = {}
local UNHEX_BYTE = {}
for i = 0, 255 do
  local h = sformat("%02x", i)
  HEX_BYTE[i] = h
  UNHEX_BYTE[h] = i
end

local function randomBytes(count)
  local t = {}
  for i = 1, count do t[i] = math.random(0, 255) end
  return t
end

local function bytesToHex(bytes)
  local parts = {}
  for i = 1, #bytes do parts[i] = HEX_BYTE[bytes[i]] end
  return tconcat(parts)
end

local function hexToBytes(hex)
  local bytes = {}
  local n = 0
  for i = 1, #hex - 1, 2 do
    local pair = hex:sub(i, i + 1)
    n = n + 1
    -- Uppercase hex isn't produced here but may arrive from elsewhere.
    bytes[n] = UNHEX_BYTE[pair] or tonumber(pair, 16)
  end
  return bytes
end

local function stringToBytes(s)
  local bytes = {}
  for i = 1, #s do bytes[i] = s:byte(i) end
  return bytes
end

local function bytesToString(bytes)
  local n = #bytes
  if n <= 200 then return string.char(table.unpack(bytes, 1, n)) end
  -- string.char has an argument limit, so chunk long messages.
  local chunks = {}
  for i = 1, n, 200 do
    chunks[#chunks + 1] = string.char(table.unpack(bytes, i, math.min(i + 199, n)))
  end
  return tconcat(chunks)
end

-- CC provides bit32, so the software bit loop this used to run (eight
-- iterations of arithmetic per byte, on every byte of every message) is only
-- needed as a fallback. Results are identical, which matters: the passphrase
-- KDF below must keep deriving the same key or previously saved private keys
-- would stop loading.
local byteXor
if bxor then
  byteXor = bxor
else
  byteXor = function(a, b)
    local result, bitv, x, y = 0, 1, a, b
    for _ = 0, 7 do
      local abit, bbit = x % 2, y % 2
      if abit ~= bbit then result = result + bitv end
      x = (x - abit) / 2
      y = (y - bbit) / 2
      bitv = bitv * 2
    end
    return result
  end
end

local function rc4Init(key)
  local S = {}
  for i = 0, 255 do S[i] = i end
  local j = 0
  local klen = #key
  for i = 0, 255 do
    j = (j + S[i] + key[(i % klen) + 1]) % 256
    S[i], S[j] = S[j], S[i]
  end
  return S
end

local function rc4Crypt(S, data)
  local s = {}
  for i = 0, 255 do s[i] = S[i] end
  local i, j = 0, 0
  local out = {}
  local xor = byteXor
  for idx = 1, #data do
    -- Wrapping by comparison rather than `% 256`: both operands are already
    -- known to be in range, so a modulo per step is wasted work.
    i = i + 1
    if i == 256 then i = 0 end
    local si = s[i]
    j = j + si
    if j >= 256 then j = j - 256 end
    local sj = s[j]
    s[i], s[j] = sj, si
    local k = si + sj
    if k >= 256 then k = k - 256 end
    out[idx] = xor(data[idx], s[k])
  end
  return out
end

-- ===========================================================================
-- High level encrypt/decrypt API.
-- ===========================================================================

-- Montgomery setup and hex parsing are pure functions of a key, and both sGps
-- hosts and clients reuse the same keys for every message, so memoise them
-- against the key table. Weak keys mean a discarded key's context goes with
-- it, and the hex fields are re-checked so mutating a key in place can't
-- serve a stale context.
local pubCache = setmetatable({}, {__mode = "k"})
local privCache = setmetatable({}, {__mode = "k"})

local function publicContext(publicKey)
  local c = pubCache[publicKey]
  if c and c.nHex == publicKey.n and c.eHex == publicKey.e then return c end
  local n = bnFromHex(publicKey.n)
  c = {
    nHex = publicKey.n, eHex = publicKey.e,
    n = n, e = bnFromHex(publicKey.e), ctx = montSetup(n)
  }
  pubCache[publicKey] = c
  return c
end

local function privateContext(privateKey)
  local c = privCache[privateKey]
  if c and c.nHex == privateKey.n and c.dHex == privateKey.d then return c end
  local n = bnFromHex(privateKey.n)
  c = {nHex = privateKey.n, dHex = privateKey.d, n = n}
  if privateKey.p and privateKey.q and privateKey.dp and privateKey.dq and
     privateKey.qinv then
    c.p = bnFromHex(privateKey.p)
    c.q = bnFromHex(privateKey.q)
    c.dp = bnFromHex(privateKey.dp)
    c.dq = bnFromHex(privateKey.dq)
    c.qinv = bnFromHex(privateKey.qinv)
    c.ctxP = montSetup(c.p)
    c.ctxQ = montSetup(c.q)
  else
    -- Key written before CRT parameters existed: still valid, just slower.
    c.d = bnFromHex(privateKey.d)
    c.ctx = montSetup(n)
  end
  privCache[privateKey] = c
  return c
end

-- RSA-encrypts a random 128-bit key, then uses it to RC4-encrypt the message.
function enc.encrypt(publicKey, message)
  assert(type(publicKey) == "table" and publicKey.n and publicKey.e,
    "enc.encrypt: publicKey must be a table with n and e")
  assert(type(message) == "string", "enc.encrypt: message must be a string")

  local ctx = publicContext(publicKey)

  local keyBytes = randomBytes(16)
  local keyBn = bnFromHex(bytesToHex(keyBytes))
  if bnCompare(keyBn, ctx.n) >= 0 then
    error("enc.encrypt: key modulus too small, use generateKeyPair(bits) with bits >= 192", 2)
  end

  local c = bnModPowCtx(keyBn, ctx.e, ctx.ctx)
  local cipherBytes = rc4Crypt(rc4Init(keyBytes), stringToBytes(message))

  return {
    key = bnToHex(c),
    data = bytesToHex(cipherBytes)
  }
end

function enc.decrypt(privateKey, package)
  assert(type(privateKey) == "table" and privateKey.n and privateKey.d,
    "enc.decrypt: privateKey must be a table with n and d")
  assert(type(package) == "table" and package.key and package.data,
    "enc.decrypt: package must be a table with key and data")

  local pk = privateContext(privateKey)
  local c = bnFromHex(package.key)

  local keyBn
  if pk.ctxP then
    -- CRT: exponentiate modulo each prime, then recombine. Both the modulus
    -- and the exponent are half-size, so this is about four times less work
    -- than one exponentiation modulo n.
    local m1 = bnModPowCtx(c, pk.dp, pk.ctxP)
    local m2 = bnModPowCtx(c, pk.dq, pk.ctxQ)

    -- (m1 - m2) has to be taken modulo p, and m2 is only bounded by q. If q
    -- happens to be the larger factor then m2 can exceed m1 + p, so reduce it
    -- into [0, p) first: bnSub assumes its first argument is the larger and
    -- would otherwise silently wrap, corrupting the recovered key.
    local m2p = m2
    if bnCompare(m2p, pk.p) >= 0 then m2p = bnMod(m2p, pk.p) end
    local diff
    if bnCompare(m1, m2p) >= 0 then
      diff = bnSub(m1, m2p)
    else
      diff = bnSub(bnAdd(m1, pk.p), m2p)
    end
    local h = bnMulMod(pk.qinv, diff, pk.p)
    keyBn = bnAdd(m2, bnMul(h, pk.q))
  else
    keyBn = bnModPowCtx(c, pk.d, pk.ctx)
  end

  local keyHex = bnToHex(keyBn)
  if #keyHex < 32 then keyHex = ("0"):rep(32 - #keyHex) .. keyHex end
  local keyBytes = hexToBytes(keyHex)

  local plainBytes = rc4Crypt(rc4Init(keyBytes), hexToBytes(package.data))
  return bytesToString(plainBytes)
end

-- ===========================================================================
-- Serialization helpers, for saving keys/packages to disk or sending them
-- over rednet as plain strings.
-- ===========================================================================

function enc.serialize(t)
  if textutils and textutils.serialize then
    return textutils.serialize(t)
  end
  local parts = {}
  for k, v in pairs(t) do parts[#parts + 1] = k .. "=" .. tostring(v) end
  return tconcat(parts, ";")
end

function enc.deserialize(str)
  if textutils and textutils.unserialize then
    local ok, val = pcall(textutils.unserialize, str)
    if ok and val then return val end
  end
  local t = {}
  for k, v in str:gmatch("(%a+)=([^;]*)") do t[k] = v end
  return t
end

-- ===========================================================================
-- Passphrase-protected key storage.
--
-- CraftOS has no filesystem permissions or disk encryption, so anything
-- written to disk in plaintext can be read by opening it with `edit`. These
-- helpers encrypt the private key at rest with a passphrase before writing
-- it, so a stray glance (or another player poking at the computer's files)
-- doesn't just hand over the key. The passphrase stretching below is a toy
-- mixing function, not a real KDF (no PBKDF2/scrypt available here) - it
-- raises the bar against casual snooping, it will not stop a determined
-- attacker who can run Lua on the same computer.
-- ===========================================================================

local function deriveKeyFromPassphrase(passphrase)
  assert(type(passphrase) == "string" and #passphrase > 0,
    "passphrase must be a non-empty string")
  -- Same mixing function as always - it has to stay bit-identical or existing
  -- saved keys stop loading. Only the byte extraction moved out of the loop.
  local bytes = {}
  for i = 1, #passphrase do bytes[i] = passphrase:byte(i) end
  local len = #bytes
  local state = {}
  for i = 1, 16 do state[i] = 0 end
  local xor = byteXor
  for round = 1, 1000 do
    for i = 1, len do
      local idx = ((i + round) % 16) + 1
      state[idx] = (xor(state[idx], bytes[i]) * 31 + round) % 256
    end
  end
  return state
end

-- Saves any key/package table to disk, encrypted with a passphrase.
function enc.saveEncrypted(path, keyTable, passphrase)
  local keyBytes = deriveKeyFromPassphrase(passphrase)
  local plaintext = enc.serialize(keyTable)
  local cipherBytes = rc4Crypt(rc4Init(keyBytes), stringToBytes(plaintext))
  local f = assert(fs.open(path, "w"), "enc.saveEncrypted: could not open " .. path)
  f.write(bytesToHex(cipherBytes))
  f.close()
end

-- Loads a key/package table saved with enc.saveEncrypted. Returns nil on a
-- wrong passphrase or corrupt file instead of throwing garbage data back.
function enc.loadEncrypted(path, passphrase)
  local f = assert(fs.open(path, "r"), "enc.loadEncrypted: could not open " .. path)
  local hex = f.readAll()
  f.close()
  local keyBytes = deriveKeyFromPassphrase(passphrase)
  local ok, plainBytes = pcall(rc4Crypt, rc4Init(keyBytes), hexToBytes(hex))
  if not ok then return nil end
  local ok2, result = pcall(enc.deserialize, bytesToString(plainBytes))
  if not ok2 or type(result) ~= "table" or not next(result) then return nil end
  return result
end

-- Plain (unencrypted) save/load, intended for the public key, which is
-- fine to leave in plaintext.
function enc.savePlain(path, keyTable)
  local f = assert(fs.open(path, "w"), "enc.savePlain: could not open " .. path)
  f.write(enc.serialize(keyTable))
  f.close()
end

function enc.loadPlain(path)
  local f = assert(fs.open(path, "r"), "enc.loadPlain: could not open " .. path)
  local str = f.readAll()
  f.close()
  return enc.deserialize(str)
end

-- ===========================================================================
-- Self-test / demo.
-- ===========================================================================

-- Exposed so the arithmetic can be exercised directly; not a stable API.
enc._internal = {
  bnFromHex = bnFromHex, bnToHex = bnToHex, bnFromInt = bnFromInt,
  bnMul = bnMul, bnAdd = bnAdd, bnSub = bnSub, bnCompare = bnCompare,
  bnDivMod = bnDivMod, bnMod = bnMod, bnModPow = bnModPow,
  bnModInverse = bnModInverse, bnBitLength = bnBitLength,
  montSetup = montSetup, bnModPowCtx = bnModPowCtx,
  millerRabin = millerRabin, rc4Init = rc4Init, rc4Crypt = rc4Crypt,
  bytesToHex = bytesToHex, hexToBytes = hexToBytes, byteXor = byteXor
}

function enc.selfTest(bits)
  bits = bits or 256
  local passed = true
  local function check(name, ok)
    print((ok and "PASS " or "FAIL ") .. name)
    passed = passed and (not not ok)
  end

  -- Arithmetic first: a wrong divide or reduction shows up here as an obvious
  -- failure rather than as an RSA round trip that mysteriously doesn't close.
  local a = bnFromHex("fedcba98765432100123456789abcdef")
  local b = bnFromHex("123456789abcdef")
  local q, r = bnDivMod(a, b)
  check("division reconstructs the dividend",
    bnCompare(bnAdd(bnMul(q, b), r), a) == 0 and bnCompare(r, b) < 0)

  -- 2^127 - 1, the Mersenne prime M127. Used both as a modulus (Montgomery
  -- needs it odd, which it is) and as the known-prime case below.
  local m = bnFromHex("7fffffffffffffffffffffffffffffff")
  check("modpow agrees with repeated squaring",
    bnCompare(bnModPow(bnFromInt(3), bnFromInt(200), m),
      (function()
        local half = bnModPow(bnFromInt(3), bnFromInt(100), m)
        return bnMulMod(half, half, m)
      end)()) == 0)
  check("modexp obeys a^(x+y) = a^x * a^y",
    bnCompare(
      bnModPow(bnFromInt(7), bnFromInt(45), m),
      bnMulMod(bnModPow(bnFromInt(7), bnFromInt(20), m),
               bnModPow(bnFromInt(7), bnFromInt(25), m), m)) == 0)
  check("modular inverse round trips",
    bnIsOne(bnMulMod(bnFromInt(65537), bnModInverse(bnFromInt(65537), m), m)))
  check("small primes sieve looks right",
    SMALL_PRIMES[1] == 3 and SMALL_PRIMES[2] == 5 and
    NUM_SMALL_PRIMES == 167 and SMALL_PRIMES[NUM_SMALL_PRIMES] == 997)
  check("miller-rabin accepts a known prime",
    millerRabin(bnFromHex("7fffffffffffffffffffffffffffffff"), 4))
  check("miller-rabin rejects known composites",
    -- 2^128-1 = (2^64-1)(2^64+1), and 2^128-3 is divisible by 11.
    not millerRabin(bnFromHex("ffffffffffffffffffffffffffffffff"), 4) and
    not millerRabin(bnFromHex("fffffffffffffffffffffffffffffffd"), 4))

  print("Generating " .. bits .. "-bit RSA key pair...")
  local pub, priv = enc.generateKeyPair(bits)
  print("n = " .. pub.n:sub(1, 24) .. "...")
  check("modulus is the product of the two factors",
    bnToHex(bnMul(bnFromHex(priv.p), bnFromHex(priv.q))) == priv.n)

  local message = "Hello, ComputerCraft! This is a secret message."
  local package = enc.encrypt(pub, message)
  local decrypted = enc.decrypt(priv, package)
  check("hybrid encrypt/decrypt round trip", decrypted == message)

  -- The CRT path and the plain path must agree, or keys saved by an older
  -- version would decrypt to garbage on a newer one.
  local legacy = {n = priv.n, d = priv.d}
  check("CRT and non-CRT decryption agree",
    enc.decrypt(legacy, package) == message)

  -- Regression: with the factors the other way round, m2 can exceed m1 + p and
  -- the recombination's subtraction wraps unless m2 is reduced modulo p first.
  -- generateKeyPair canonicalises p > q, so this shape has to be built by hand.
  check("decryption survives reversed factor ordering",
    (function()
      local reversed = {
        n = priv.n, d = priv.d,
        p = priv.q, q = priv.p, dp = priv.dq, dq = priv.dp,
        qinv = bnToHex(bnModInverse(bnFromHex(priv.p), bnFromHex(priv.q)))
      }
      return enc.decrypt(reversed, package) == message
    end)())

  local empty = enc.encrypt(pub, "")
  check("empty message round trips", enc.decrypt(priv, empty) == "")

  local long = ("abcdefghij"):rep(60)
  check("long message round trips",
    enc.decrypt(priv, enc.encrypt(pub, long)) == long)

  check("wrong key does not recover the message",
    (function()
      local _, other = enc.generateKeyPair(192)
      local ok, out = pcall(enc.decrypt, other, package)
      return (not ok) or out ~= message
    end)())

  print(passed and "SELF TEST PASSED" or "SELF TEST FAILED")
  return passed
end

function enc.bench(bits)
  bits = bits or 256
  local function ms() return os.epoch("utc") end

  local t0 = ms()
  local pub, priv = enc.generateKeyPair(bits)
  print(sformat("keygen %d-bit : %d ms", bits, ms() - t0))

  local message = ("payload "):rep(8)
  local pkg
  local t1 = ms()
  for _ = 1, 10 do pkg = enc.encrypt(pub, message) end
  print(sformat("encrypt       : %.1f ms", (ms() - t1) / 10))

  local t2 = ms()
  for _ = 1, 10 do enc.decrypt(priv, pkg) end
  print(sformat("decrypt (CRT) : %.1f ms", (ms() - t2) / 10))

  local legacy = {n = priv.n, d = priv.d}
  local t3 = ms()
  for _ = 1, 10 do enc.decrypt(legacy, pkg) end
  print(sformat("decrypt (n,d) : %.1f ms", (ms() - t3) / 10))
end

local progArgs = {...}
if progArgs[1] == "test" then
  enc.selfTest(tonumber(progArgs[2]) or 256)
elseif progArgs[1] == "bench" then
  enc.bench(tonumber(progArgs[2]) or 256)
end

return enc
