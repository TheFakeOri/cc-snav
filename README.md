# cc-snav

A secure navigation stack for ComputerCraft, built bottom-up: encryption →
authenticated messaging → jam-resistant GPS → autopilot for Create Aeronautics
ships.

Each layer is usable on its own, and each has a self-test you can run without
any hardware.

## Install

On any computer with HTTP enabled:

```
wget run https://raw.githubusercontent.com/TheFakeOri/cc-snav/main/install.lua
```

It asks what the computer is (GPS host / helicopter / operator console),
downloads what that role needs, writes its config, and sets it to run on boot.

Non-interactive:

```
install host 128 72 -340     GPS host at those coordinates
install heli                 the helicopter
install pilot                an operator console
install watch                prints coordinates as they change
```

`watch` is the quickest way to confirm the constellation works — it prints the
position whenever it moves and stays quiet when it doesn't. Every install also
gets `watch.lua` and `gpsdiag.lua`, since you want them present *before* the
radio starts misbehaving.

## When fixes fail

```
gpsdiag
```

Pings each host individually over several rounds and tells you which answered,
how far away they are, how long they took, and whether the hosts are arranged
well enough to solve from. It distinguishes the two real causes:

- **Not enough hosts answering** — radio range or a host that isn't running.
  Wireless modem range in CC:Tweaked depends on altitude, so low hosts reach far
  less than high ones and marginal links come and go — which is what makes fixes
  work only *sometimes*. `gpsdiag` flags hosts as `always` / `INTERMITTENT` /
  `NEVER` so you can tell which.
- **All hosts answering but fixes still failing** — geometry. Hosts all at the
  same altitude can't pin down height. Move one well above or below the rest.

## Layers

| File | What it does |
|---|---|
| `enc.lua` | RSA keygen + hybrid RSA/RC4 encryption, and passphrase-protected key storage |
| `sip.lua` | Authenticated, encrypted messaging over rednet, with replay rejection |
| `sgps/sGps.lua` | GPS that only trusts pinned hosts, requires a quorum, and rejects outliers |
| `nav/sNav.lua` | Autopilot: GPS-derived inertial estimator, learned flight model, remote control |

Entry points: `gpshost.lua`, `heli.lua`, `pilot.lua`, `watch.lua`. Helpers:
`install.lua`, `publish.lua`, `diskstartup.lua`.

## Upgrading an existing constellation

**Update the computers in any order.** The sGps request/response protocol is
versioned (`sgps.PROTOCOL_VERSION`, currently 2). A v2 client asks for a
symmetric reply; a host that predates that ignores the request field and
answers the old RSA way, and a v2 client accepts either shape. So a half-updated
constellation keeps working — it just doesn't get the speedup until both ends of
a given pair are updated. `gpsdiag` is the quickest way to see what you have.

Two behaviour changes worth knowing before you reboot everything:

- **A wired modem is now a loud failure, not a silent one.** sGps needs the
  block distance that only a wireless `modem_message` reports, so a computer
  that picked up a wired modem got zero fixes while looking perfectly
  connected. Autodetection now prefers wireless and refuses a wired-only
  computer with an explanation. Set `sgps.ALLOW_WIRED_MODEM` if you really want
  the old behaviour.
- **Outlier rejection needs six hosts** to identify a liar, where it previously
  claimed to manage with five. It did not actually manage it — see the setup
  notes below.

## Self-tests

```
enc.lua test
sip.lua test
sGps.lua test
sNav.lua test
```

106 assertions across the four, none of which need a modem, GPS host or ship.
`enc.lua bench` times the crypto primitives; `sNav.lua wiring` prints the
redstone wiring reference.

## Setting it up

1. **GPS constellation.** Four or more computers with wireless modems, at
   surveyed positions. Do *not* put them all at the same Y — coplanar hosts
   give the solver nothing vertical to work with. Install each as `host` with
   its exact F3 coordinates, and note the computer ID and key fingerprint it
   prints.

   Four is the minimum to *get* a fix. **Six is the minimum for a lying or
   compromised host to be identifiable.** Four points determine a position
   exactly, so with five hosts, dropping the suspect one leaves four that fit
   any claims perfectly and the data cannot say who lied — sGps refuses
   (`inconsistent_hosts`) rather than return a confident wrong answer. With six
   it identifies and drops the liar. Wireless modems are cheap; run six.
2. **The ship.** Install as `heli`, giving it those host IDs and the operator's
   ID. Wire the controls (`sNav.lua wiring`). Centre a stepped tail by hand
   before first boot.
3. **Calibrate.** On first run it offers to measure the ship's real top speed,
   acceleration, braking, turn rate and climb rate. It flies at full throttle
   to do this — somewhere high and open.
4. **Fly.** Install an operator console as `pilot`, then `goto <x> <y> <z>`.

## Security

The interesting part is the trust model, not the cipher. Vanilla `gps.locate()`
believes whoever answers; sGps accepts a position only from a computer whose
public key it has pinned, requires a quorum of them, embeds a nonce so old
replies can't be replayed, and drops hosts whose claims don't fit the others.
Commands to a ship are encrypted to its key and accepted only from authorised
computer IDs.

**But treat the cryptography as obfuscation, not protection.** It is a toy RSA
implementation with RC4 and a non-cryptographic checksum, on a platform with no
secure random source. It will stop casual spoofing, snooping and replay between
players. It will not stop someone determined. Details are in each file's header.

A position response is encrypted symmetrically, under a fresh 16-byte key the
client sends inside its RSA-encrypted request, and carries an 8-byte keyed tag.
The tag is a keyed checksum, not a real MAC — there is no hash function in this
project. The echoed nonce proves the reply is fresh and that its writer knew
that key; the tag is what covers RC4's malleability. Neither proves the
position *claim* is true, which is what the quorum and outlier rejection are
for.

Two practical notes:

- **Change the passphrases after installing.** The `passphrase` fields ship as
  `"change-this-passphrase"`. They live in plaintext next to the keys they
  protect (unavoidable for unattended boot), so they stop someone reading a key
  out with `edit`, nothing more.
- **The estimator still dead-reckons between fixes**, so fly with margin. Fix
  latency used to dominate everything; it no longer does — see Performance.

## Performance

The RSA underneath every message used to set the pace for the whole stack, and
a position fix cost several RSA operations. Three changes in `enc.lua` removed
most of that: Montgomery reduction instead of divide-and-remainder in the
modular-multiply inner loop, Knuth long division where a real division is still
needed, and Chinese-remainder private keys (two exponentiations modulo the
half-size primes rather than one modulo `n`). `sGps.lua` then stopped needing an
RSA private-key operation per host per fix at all.

Measured under CraftOS-PC on 256-bit keys, before and after:

| | before | after |
|---|---|---|
| Key generation | 2495 ms | 21 ms |
| Encrypt (public key) | 11.4 ms | 0.5 ms |
| Decrypt (private key) | 264 ms | 2.1 ms |
| Client crypto per 4-host fix | ~1100 ms | ~2.2 ms |

Treat those as relative, not absolute: CraftOS-PC runs native Lua, while in
Minecraft this is Cobalt on the JVM sharing one thread with every other
computer, so real figures are slower. The point is the ratio — crypto is no
longer what limits the fix rate. Radio round trips and Minecraft's 20 ticks a
second are, which makes `nav.FIX_INTERVAL` of one second comfortable.

`enc.lua bench` prints the numbers on your own machine.

Old keys still work. Private keys gained CRT parameters, but `d` is still
stored and used when they're absent, so a keypair generated by an earlier
version decrypts unchanged.

## Requirements

- CC:Tweaked, HTTP enabled for the installer
- Wireless modems — sGps needs the real block-distance a wireless
  `modem_message` reports, which wired modems don't provide
- Create (Redstone Links, Sequenced Gearshift) and Create Aeronautics for the
  autopilot layer; the lower three layers need neither
