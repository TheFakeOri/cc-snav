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
```

## Layers

| File | What it does |
|---|---|
| `enc.lua` | RSA keygen + hybrid RSA/RC4 encryption, and passphrase-protected key storage |
| `sip.lua` | Authenticated, encrypted messaging over rednet, with replay rejection |
| `sgps/sGps.lua` | GPS that only trusts pinned hosts, requires a quorum, and rejects outliers |
| `nav/sNav.lua` | Autopilot: GPS-derived inertial estimator, learned flight model, remote control |

Entry points: `gpshost.lua`, `heli.lua`, `pilot.lua`. Helpers: `install.lua`,
`publish.lua`, `diskstartup.lua`.

## Self-tests

```
enc.lua test
sip.lua test
sGps.lua test
sNav.lua test
```

`sNav.lua wiring` prints the redstone wiring reference.

## Setting it up

1. **GPS constellation.** Four or more computers with wireless modems, at
   surveyed positions. Do *not* put them all at the same Y — coplanar hosts
   give the solver nothing vertical to work with. Install each as `host` with
   its exact F3 coordinates, and note the computer ID and key fingerprint it
   prints.
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

Two practical notes:

- **Change the passphrases after installing.** The `passphrase` fields ship as
  `"change-this-passphrase"`. They live in plaintext next to the keys they
  protect (unavoidable for unattended boot), so they stop someone reading a key
  out with `edit`, nothing more.
- **Fix latency dominates flight.** Expect a position fix every one to a few
  seconds; the estimator dead-reckons between them. Fly with margin.

## Requirements

- CC:Tweaked, HTTP enabled for the installer
- Wireless modems — sGps needs the real block-distance a wireless
  `modem_message` reports, which wired modems don't provide
- Create (Redstone Links, Sequenced Gearshift) and Create Aeronautics for the
  autopilot layer; the lower three layers need neither
