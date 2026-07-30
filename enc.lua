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
  a test message.
]]

local enc = {}

math.randomseed((os.epoch and os.epoch("utc")) or os.time())

-- ===========================================================================
-- CC watchdog helper: pure-Lua bignum math can run long enough to trip
-- ComputerCraft's "too long without yielding" abort. Queuing and pulling a
-- private event resets that timer without any real delay.
-- ===========================================================================

local function yieldTick()
  os.queueEvent("enc_lua_yield")
  os.pullEvent("enc_lua_yield")
end

-- ===========================================================================
-- Bignum: unsigned arbitrary precision integers.
-- Represented as little-endian arrays of base-2^24 limbs (chosen so a limb
-- maps to exactly 6 hex digits, and limb*limb products stay well under the
-- 2^53 integer precision of Lua's doubles).
-- ===========================================================================

local BASE = 16777216 -- 2^24
local BASE_BITS = 24

local function trim(a)
  local n = #a
  while n > 1 and a[n] == 0 do
    a[n] = nil
    n = n - 1
  end
  return a
end

local function bnFromInt(x)
  if x == 0 then return {0} end
  local res = {}
  while x > 0 do
    res[#res + 1] = x % BASE
    x = math.floor(x / BASE)
  end
  return res
end

local function bnCopy(a)
  local res = {}
  for i = 1, #a do res[i] = a[i] end
  return res
end

local function bnCompare(a, b)
  local la, lb = #a, #b
  while la > 1 and a[la] == 0 do la = la - 1 end
  while lb > 1 and b[lb] == 0 do lb = lb - 1 end
  if la ~= lb then return la < lb and -1 or 1 end
  for i = la, 1, -1 do
    if a[i] ~= b[i] then return a[i] < b[i] and -1 or 1 end
  end
  return 0
end

local function bnAdd(a, b)
  local res = {}
  local carry = 0
  local n = math.max(#a, #b)
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
      v = v + BASE
      borrow = 1
    else
      borrow = 0
    end
    res[i] = v
  end
  return trim(res)
end

local function bnSubOne(a) return bnSub(a, {1}) end

local function bnMul(a, b)
  local res = {}
  for i = 1, #a + #b do res[i] = 0 end
  for i = 1, #a do
    if a[i] ~= 0 then
      local carry = 0
      for j = 1, #b do
        local v = res[i + j - 1] + a[i] * b[j] + carry
        carry = math.floor(v / BASE)
        res[i + j - 1] = v - carry * BASE
      end
      local k = i + #b
      while carry > 0 do
        local v = res[k] + carry
        carry = math.floor(v / BASE)
        res[k] = v - carry * BASE
        k = k + 1
      end
    end
  end
  return trim(res)
end

local function bnIsZero(a)
  trim(a)
  return #a == 1 and a[1] == 0
end

local function bnIsOne(a)
  trim(a)
  return #a == 1 and a[1] == 1
end

local function bnIsEven(a) return a[1] % 2 == 0 end

local function bnBitLength(a)
  trim(a)
  if #a == 1 and a[1] == 0 then return 0 end
  local top = a[#a]
  local bits = (#a - 1) * BASE_BITS
  while top > 0 do
    bits = bits + 1
    top = math.floor(top / 2)
  end
  return bits
end

local function bnTestBit(a, i)
  local limbIndex = math.floor(i / BASE_BITS) + 1
  local bitIndex = i % BASE_BITS
  local limb = a[limbIndex] or 0
  return math.floor(limb / (2 ^ bitIndex)) % 2 == 1
end

local function bnSetBit(q, i)
  local limbIndex = math.floor(i / BASE_BITS) + 1
  local bitIndex = i % BASE_BITS
  while #q < limbIndex do q[#q + 1] = 0 end
  q[limbIndex] = q[limbIndex] + (2 ^ bitIndex)
  return q
end

local function bnShiftLeft1(a)
  local res = {}
  local carry = 0
  for i = 1, #a do
    local v = a[i] * 2 + carry
    if v >= BASE then
      res[i] = v - BASE
      carry = 1
    else
      res[i] = v
      carry = 0
    end
  end
  if carry > 0 then res[#res + 1] = carry end
  return res
end

local function bnShiftRight1(a)
  local res = {}
  local carry = 0
  for i = #a, 1, -1 do
    local v = a[i] + carry * BASE
    res[i] = math.floor(v / 2)
    carry = v % 2
  end
  return trim(res)
end

-- long division via bit-by-bit restoring division; fast enough since it's
-- O(bits(a)) iterations rather than O(bits(a)*bits(b))
local function bnDivMod(a, b)
  if bnIsZero(b) then error("enc: division by zero", 2) end
  if bnCompare(a, b) < 0 then return {0}, bnCopy(a) end
  local nbits = bnBitLength(a)
  local q, r = {0}, {0}
  for i = nbits - 1, 0, -1 do
    r = bnShiftLeft1(r)
    if bnTestBit(a, i) then r[1] = r[1] + 1 end
    if bnCompare(r, b) >= 0 then
      r = bnSub(r, b)
      q = bnSetBit(q, i)
    end
  end
  return trim(q), trim(r)
end

local function bnMod(a, m)
  local _, r = bnDivMod(a, m)
  return r
end

local function bnMulMod(a, b, m)
  local p = bnMul(a, b)
  local _, r = bnDivMod(p, m)
  return r
end

local function bnModPow(base, exp, mod)
  local result = bnFromInt(1)
  base = bnMod(base, mod)
  local e = bnCopy(exp)
  local ticks = 0
  while not bnIsZero(e) do
    if not bnIsEven(e) then
      result = bnMulMod(result, base, mod)
    end
    base = bnMulMod(base, base, mod)
    e = bnShiftRight1(e)
    ticks = ticks + 1
    if ticks % 8 == 0 then yieldTick() end
  end
  return result
end

local function bnGcd(a, b)
  a, b = bnCopy(a), bnCopy(b)
  while not bnIsZero(b) do
    local _, r = bnDivMod(a, b)
    a, b = b, r
  end
  return a
end

local function bnModSmall(a, m)
  local r = 0
  for i = #a, 1, -1 do
    r = (r * BASE + a[i]) % m
  end
  return r
end

local function bnToHex(a)
  trim(a)
  local parts = {}
  for i = #a, 1, -1 do
    if i == #a then
      parts[#parts + 1] = string.format("%x", a[i])
    else
      parts[#parts + 1] = string.format("%06x", a[i])
    end
  end
  return table.concat(parts)
end

local function bnFromHex(hex)
  hex = hex:gsub("^0[xX]", "")
  if hex == "" then return {0} end
  local pad = (6 - (#hex % 6)) % 6
  hex = string.rep("0", pad) .. hex
  local res = {}
  local nlimbs = #hex / 6
  for i = 1, nlimbs do
    local chunk = hex:sub(#hex - i * 6 + 1, #hex - (i - 1) * 6)
    res[i] = tonumber(chunk, 16)
  end
  return trim(res)
end

-- ===========================================================================
-- Signed bignum wrapper, only needed for the extended Euclidean algorithm
-- used to compute the RSA private exponent.
-- ===========================================================================

local function sgnFromMag(mag, sign)
  if bnIsZero(mag) then sign = 1 end
  return {sign = sign, mag = mag}
end

local function sgnNeg(s) return sgnFromMag(s.mag, -s.sign) end

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
  end
  return old_r, old_s
end

local function bnModInverse(e, phi)
  local g, x = bnExtGcd(e, phi)
  if not bnIsOne(g) then return nil end
  local _, r = bnDivMod(x.mag, phi)
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
  local half = math.floor(2 ^ (topBits - 1))
  res[nlimbs] = math.random(0, math.max(half - 1, 0)) + half
  return trim(res)
end

local SMALL_PRIMES = {
  3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73,
  79, 83, 89, 97, 101, 103, 107, 109, 113
}

local function passesTrialDivision(n)
  for _, p in ipairs(SMALL_PRIMES) do
    if bnModSmall(n, p) == 0 then return false end
  end
  return true
end

local function millerRabin(n, rounds)
  local nMinus1 = bnSubOne(n)
  local two = bnFromInt(2)
  local d = bnCopy(nMinus1)
  local s = 0
  while bnIsEven(d) do
    d = bnShiftRight1(d)
    s = s + 1
  end
  for _ = 1, rounds do
    local a
    repeat
      a = bnRandomBits(bnBitLength(n))
    until bnCompare(a, two) >= 0 and bnCompare(a, nMinus1) < 0
    local x = bnModPow(a, d, n)
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
    yieldTick()
  end
  return true
end

local function generateProbablePrime(bits)
  while true do
    local candidate = bnRandomBits(bits)
    if candidate[1] % 2 == 0 then candidate[1] = candidate[1] + 1 end
    if passesTrialDivision(candidate) and millerRabin(candidate, 8) then
      return candidate
    end
    yieldTick()
  end
end

-- ===========================================================================
-- RSA key generation.
-- ===========================================================================

function enc.generateKeyPair(bits)
  bits = bits or 256
  assert(type(bits) == "number" and bits % 2 == 0 and bits >= 192,
    "enc.generateKeyPair: bits must be an even number >= 192 (256+ recommended)")

  local half = bits / 2
  local e = bnFromInt(65537)
  local p, q, n, phi, d

  while true do
    p = generateProbablePrime(half)
    repeat
      q = generateProbablePrime(half)
    until bnCompare(p, q) ~= 0

    n = bnMul(p, q)
    phi = bnMul(bnSubOne(p), bnSubOne(q))

    if bnIsOne(bnGcd(e, phi)) then
      d = bnModInverse(e, phi)
      break
    end
  end

  local publicKey = {n = bnToHex(n), e = bnToHex(e)}
  local privateKey = {n = bnToHex(n), d = bnToHex(d)}
  return publicKey, privateKey
end

-- ===========================================================================
-- Byte/hex helpers + RC4 stream cipher for the symmetric message body.
-- ===========================================================================

local function randomBytes(count)
  local t = {}
  for i = 1, count do t[i] = math.random(0, 255) end
  return t
end

local function bytesToHex(bytes)
  local parts = {}
  for i = 1, #bytes do parts[i] = string.format("%02x", bytes[i]) end
  return table.concat(parts)
end

local function hexToBytes(hex)
  local bytes = {}
  for i = 1, #hex, 2 do
    bytes[#bytes + 1] = tonumber(hex:sub(i, i + 1), 16)
  end
  return bytes
end

local function stringToBytes(s)
  local bytes = {}
  for i = 1, #s do bytes[i] = s:byte(i) end
  return bytes
end

local function bytesToString(bytes)
  local chars = {}
  for i = 1, #bytes do chars[i] = string.char(bytes[i]) end
  return table.concat(chars)
end

local function byteXor(a, b)
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
  for idx = 1, #data do
    i = (i + 1) % 256
    j = (j + s[i]) % 256
    s[i], s[j] = s[j], s[i]
    local k = s[(s[i] + s[j]) % 256]
    out[idx] = byteXor(data[idx], k)
  end
  return out
end

-- ===========================================================================
-- High level encrypt/decrypt API.
-- ===========================================================================

-- RSA-encrypts a random 128-bit key, then uses it to RC4-encrypt the message.
function enc.encrypt(publicKey, message)
  assert(type(publicKey) == "table" and publicKey.n and publicKey.e,
    "enc.encrypt: publicKey must be a table with n and e")
  assert(type(message) == "string", "enc.encrypt: message must be a string")

  local n = bnFromHex(publicKey.n)
  local e = bnFromHex(publicKey.e)

  local keyBytes = randomBytes(16)
  local keyBn = bnFromHex(bytesToHex(keyBytes))
  if bnCompare(keyBn, n) >= 0 then
    error("enc.encrypt: key modulus too small, use generateKeyPair(bits) with bits >= 192", 2)
  end

  local c = bnModPow(keyBn, e, n)
  local S = rc4Init(keyBytes)
  local cipherBytes = rc4Crypt(S, stringToBytes(message))

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

  local n = bnFromHex(privateKey.n)
  local d = bnFromHex(privateKey.d)

  local c = bnFromHex(package.key)
  local keyBn = bnModPow(c, d, n)
  local keyHex = bnToHex(keyBn)
  keyHex = string.rep("0", 32 - #keyHex) .. keyHex
  local keyBytes = hexToBytes(keyHex)

  local S = rc4Init(keyBytes)
  local cipherBytes = hexToBytes(package.data)
  local plainBytes = rc4Crypt(S, cipherBytes)

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
  return table.concat(parts, ";")
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
  local state = {}
  for i = 1, 16 do state[i] = 0 end
  for round = 1, 1000 do
    for i = 1, #passphrase do
      local idx = ((i + round) % 16) + 1
      state[idx] = byteXor(state[idx], passphrase:byte(i))
      state[idx] = (state[idx] * 31 + round) % 256
    end
  end
  return state
end

-- Saves any key/package table to disk, encrypted with a passphrase.
function enc.saveEncrypted(path, keyTable, passphrase)
  local keyBytes = deriveKeyFromPassphrase(passphrase)
  local plaintext = enc.serialize(keyTable)
  local S = rc4Init(keyBytes)
  local cipherBytes = rc4Crypt(S, stringToBytes(plaintext))
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
  local S = rc4Init(keyBytes)
  local ok, plainBytes = pcall(rc4Crypt, S, hexToBytes(hex))
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

function enc.selfTest(bits)
  bits = bits or 256
  print("Generating " .. bits .. "-bit RSA key pair (may take a few seconds)...")
  local pub, priv = enc.generateKeyPair(bits)
  print("n = " .. pub.n:sub(1, 24) .. "...")

  local message = "Hello, ComputerCraft! This is a secret message."
  local package = enc.encrypt(pub, message)
  local decrypted = enc.decrypt(priv, package)

  print("Original : " .. message)
  print("Decrypted: " .. decrypted)
  local ok = decrypted == message
  print(ok and "SELF TEST PASSED" or "SELF TEST FAILED")
  return ok
end

local progArgs = {...}
if progArgs[1] == "test" then
  enc.selfTest(tonumber(progArgs[2]) or 256)
end

return enc
