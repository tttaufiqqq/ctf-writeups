# 08 - Crownspire Transfer

**Category:** ICS
**Points:** 975
**Difficulty:** Medium
**Solved:** 28/07/2026 21:00
**Flag:** `HTB{104_stale_handoff_tripped_52t_7af9eecb0051aa2fef9140cc3db5394e}`

**Approach & tooling note:**

- I used Claude Code as a supporting/execution aid for this one:
  - Decoding the IEC 60870-5-104 pcap byte-by-byte against Wireshark's own dissection to sanity-check my framing.
  - Writing a small raw-socket IEC-104 client from scratch (no library, since the "maintenance proof" mechanic in this challenge isn't a real part of the standard).
  - Running the repeated probing/sweeping scripts.
- The actual investigative calls were mine:
  - Recognizing that the two exposed ports needed to be told apart by protocol behaviour rather than guessed.
  - Deciding *not* to port-scan the host further once I noticed the two given ports sat inside Kubernetes' NodePort range (that's shared CTF infrastructure - scanning beyond the two ports HTB explicitly gave me risks hitting other players' instances, so I didn't).
  - Spotting that "stale maintenance proof accepted" was a materially different message from "bad proof rejected" and was worth chasing rather than dismissing as noise.
  - Working out - once authorized - which control IOA did what by actually reading the state deltas rather than assuming the pcap's demo IOAs (1101/1201) carried over unchanged to the live instance (they didn't - 1101 turned out to be something else entirely on the live RTU).
- Every claim below was checked against raw `status.json`/`alarms` output before I trusted it. Happy to walk through this live if asked.

## Challenge Description

> Stormcrews found a Frostline feeder RTU still guarding the Crownspire
> east transfer bus. The live HMI shows a loaded transfer pump and a
> transfer breaker held open by an interlock. Recover enough control to
> force the unsafe transfer and collect the checkpoint token from the
> resulting feeder-trip alarm.

- Translating the lore: this is a live ICS/SCADA challenge.
- "RTU" (Remote Terminal Unit) + "feeder" + "interlock" all point at a real substation automation protocol - most likely IEC 60870-5-104, since that's the standard TCP-based ICS protocol you'd realistically find guarding a "transfer bus" between two breakers.
- "Recover enough control to force the unsafe transfer" means: get past whatever's stopping me from closing a breaker that's *supposed* to stay open, and do it anyway.

## Step 1 - The pcap: establishing the protocol shape

- The scenario gave one file, `backup.pcap` (48 packets, ~4.7KB). Wireshark confirmed IEC 60870-5-104 immediately:

```
$ tshark -r backup.pcap -q -z io,phs
  iec60870_104     frames:23 bytes:2031
    iec60870_asdu  frames:18 bytes:1641
```

- Dumping the ASDUs showed two separate TCP sessions.
- The interesting one (the second) walked through a completely standard IEC-104 control sequence: `STARTDT`, a general interrogation (`C_IC_NA_1`), a clock sync (`C_CS_NA_1`), then two `C_SC_NA_1` (single command) sequences - one on IOA 1101 (select `0x81` then execute `0x01` - i.e. close), one on IOA 1201 (same pattern - i.e. turn on).
- Common address (CA) was 17 throughout.
- I decoded these by hand against Wireshark's own field extraction to make sure I had the byte layout right (`TypeId | VSQ | COT | OA | CA(2) | IOA(3) | data`), since I'd be hand-rolling frames later and needed to trust my own encoder:

```
2d 01 06 00 11 00 4d 04 00 81
TypeId=0x2d(45=C_SC_NA_1) VSQ=01 COT=06(Act) OA=00 CA=0x0011(17)
IOA=0x00044d(1101) SCO=0x81(select, close)
```

- I initially read this pcap as "the answer key" - close 1101, turn on 1201, done. That turned out to be wrong (see Step 5), but it did establish the protocol shape and CA=17 correctly, which mattered later.
- One frame stood out as *not* standard IEC-104: frame 8, TypeId 0x68 (104).
  - The real standard type 104 (`C_TS_NA_1`, an obsolete "test command") carries a fixed 2-byte 0x55AA pattern at IOA 0 - no custom IOA, no 8-byte payload.
  - This frame instead had `IOA=266500` and an 8-byte trailing blob: `bb 32 24 56 bd a8 7c ee`.
  - That's not standard protocol at all - it's something the challenge author bolted on top of IEC-104 for this scenario.
  - I flagged it as probably an authentication or "maintenance handoff" mechanic and kept the raw bytes for later.

## Step 2 - Spawning the docker and telling the two ports apart

- The instance card gave two unlabeled `IP:PORT` pairs. Rather than guess which was which, I probed both:

```
$ curl -sv --max-time 5 http://<ip>:30219/   # empty reply, no HTTP
$ curl -sv --max-time 5 http://<ip>:32277/   # HTTP/1.0 200, Server: FrostlineHMI/2.8 Python/3.12.3
```

- 30219 was silent on an HTTP probe (consistent with a raw binary protocol).
- 32277 answered as a plain Python `http.server`-based HMI (not Flask - the 404/501 error bodies were the stock `BaseHTTPRequestHandler` pages, not a Werkzeug debug page, so that avenue was closed early).
- The HMI page (`/`) was a static SVG mimic diagram pulling live state from two endpoints, `/status.json` and `/alarms`, both read-only GET.
- I checked for a wider API surface (`OPTIONS`, `POST`, `PUT`, path traversal, alternate methods) - nothing; the HMI is genuinely observation-only. All control has to happen over the raw IEC-104 port, 30219.
- Both ports (30219, 32277) fell inside Kubernetes' NodePort range (30000-32767).
  - That told me this challenge runs on a shared cluster alongside other competitors' instances - so I deliberately did not nmap-sweep the host looking for a hidden third port.
  - Scanning beyond what HTB explicitly handed me on the instance card isn't something I had authorization for on shared infrastructure.
- `/status.json` gave the live process model:

```json
{
  "authorized": false, "authorized_ttl": 0.0,
  "last_handoff": "none", "last_command": "boot",
  "process": {
    "main_breaker_closed": true, "tie_breaker_closed": false,
    "transfer_pump_running": true, "interlock_bypass": false,
    "feeder_trip": false, "sync_angle_deg": 12.6, ...
  }
}
```

- Main breaker (52-M) closed, tie breaker (52-T) open and inhibited by a phase-angle interlock, pump (P-43) running and loaded. Exactly what the lore described.

## Step 3 - Building an IEC-104 client and hitting a wall

- I wrote a small raw-socket client (no library - the custom type-104 frame meant I'd be crafting non-standard ASDUs anyway) handling `STARTDT`/S-frame sequence numbers and generic ASDU building.
- First thing I tried: replay the pcap's exact close/on commands (IOA 1101, 1201) with proper select-then-execute framing.
- Every single control command - regardless of type (`C_SC_NA_1`, `C_DC_NA_1`, `C_RC_NA_1`, `C_SE_NC_1`) or IOA (I swept 1101-1105, 1201-1203, 1301...) - came back rejected at the *execute* stage with the same reason, visible in `status.json`:

```json
"last_command": "IOA 1101 rejected: no active handoff"
```

- Interestingly, `SELECT` always succeeded (positive `ActCon`) - only `EXECUTE` was gated. That confirmed the auth check sits specifically at the execute/apply step, not earlier, but didn't give me a way in.

## Step 4 - The dead end (worth documenting in full)

- This took the longest and is worth writing up honestly rather than skipping to the answer.
- I connected frame 8's oddity (`TypeId=104`, `IOA=266500`, 8-byte blob) to the `"no active handoff"` message and tried replaying it byte-for-byte:

```python
asdu = build_asdu(104, cot=6, ioa=266500, ca=17,
                   data=bytes.fromhex("bb322456bda87cee"))
```

- Result: `"last_handoff": "bad proof rejected"`, event `"AUTH: maintenance proof rejected."`.
- My first assumption was the obvious one - this is a per-instance random secret (HMAC-style), and an old pcap capture simply can't reproduce it. I spent a long stretch trying to either derive it or route around it entirely, and ruled out, in order:
  - **Unkeyed CRC64/hash of public fields.** Tried CRC64 (ECMA/ISO/Jones variants) and hashlib truncations of the ASDU header bytes, CA, IOA, and every device-identity string visible in `status.json`, against the target 8 bytes. No match.
  - **HMAC with a dictionary of plausible keys** (`frostline`, `crownspire`, `maintenance`, `RLY-104`, etc.) over the same message candidates. No match.
  - **A wire-level timing side-channel.** I noticed type-104 commands never get an ASDU-level response at all (confirmed by watching raw frames - only spontaneous telemetry, never an echoed TypeId=104 reply) - so there's no per-byte comparison timing to measure over the wire in the first place. Dead end before it started.
  - **Automatic/periodic legitimate re-authorization.** Watched `status.json` continuously for ~2 minutes for any spontaneous `authorized` flip. Nothing.
  - **Direction-confusion injection.** IEC-104 has separate monitor (RTU->master) and control (master->RTU) type IDs. I tried sending a monitor-direction `M_ME_NC_1` (measured-value report, normally RTU-only) *from* the client, straight at the sync-angle IOA (2103), hoping the server didn't validate direction. It correctly rejected it as `COT=44` ("unknown type"), so direction validation was solid.
  - **A DES angle**, since 8 bytes is exactly one DES block. Tried DES-ECB over the same key/plaintext candidate space. No match.
  - **Simple XOR-cipher against time-derived values.** Checked whether `target XOR time_bucket` produced readable ASCII (would reveal a human key immediately). It didn't, for any bucket size I tried.
- At this point I reported back that I'd hit a genuine wall, not just a hard problem - every angle I could think of from the wire alone was closed off, and said so plainly rather than guessing further in silence.

## Step 5 - The actual crack: re-reading "stale" correctly

- While testing a completely unrelated hypothesis (whether a legitimate control command type might slip past the gate on a *measurement* IOA instead of a *control* IOA), I noticed `last_handoff` had changed to a message I hadn't seen before:

```json
"last_handoff": "stale maintenance proof accepted"
```

- This came from resending the exact pcap bytes again.
- My first read was "that's probably just a duplicate-submission tag, not real progress" - so I tested that directly before getting excited: I generated a brand new random 8-byte value and sent it three times in a row. Every single time, flat `"bad proof rejected"` - never `"stale...accepted"`, no matter how many times I repeated it.
- That ruled out "duplicate detection" and confirmed the pcap's specific value really is structurally recognized by the server, unlike genuine garbage.
- I then checked how strict the match was, flipping one bit at a time in the known value (first byte, last byte, a middle byte) and resending. Every single-bit-flipped variant went straight back to flat rejection - only the byte-exact original ever produced the "stale" response.
- So this wasn't a fuzzy/prefix match bug; it's an exact match against something the server genuinely recognizes as a legacy-valid credential.
- Then the actual breakthrough, resending the untouched value one more time:

```json
"authorized": true,
"authorized_ttl": 28.7,
"last_handoff": "stale maintenance proof accepted"
```

- `authorized` was `true`.
- The "stale" wording was flavour text for a legacy/backward-compatible maintenance override, not a sign of cryptographic expiry - and it only fires probabilistically (roughly one success in every 4-8 resends in my testing, not deterministically).
- The fix was simple once understood: loop resending the exact captured proof until `authorized` flips true, then act immediately inside the ~30 second window before the TTL lapses.

## Step 6 - Finding the real control IOAs (the pcap's demo mapping doesn't carry over)

- With `authorized: true`, I could finally test control commands for real - and the pcap's demo IOAs turned out to be *misleading* as a direct map to the live system:

```
IOA 1101: last_command = "interlock bypass set to 1"   <- not a breaker!
IOA 1201: last_command = "52-T close caused phase-slip trip"   <- the tie breaker
```

- The pcap's demo session only ever established the wire *format* for select/execute commands - the actual point mapping on the live RTU had to be found by sweeping IOAs inside a live authorized window and reading what `status.json` actually changed, not by assuming pcap addressing carried over unchanged.
- Sequence that worked, re-authorizing as needed to keep the window open:

```python
send_handoff()                       # loop until authorized == true
close_via_select_execute(ioa=1101)   # -> process.interlock_bypass = true
close_via_select_execute(ioa=1201)   # -> tie breaker closes into an
                                      #    out-of-phase bus with the
                                      #    pump still loaded
```

- `status.json` immediately showed the fault:

```json
"last_command": "52-T close caused phase-slip trip",
"process": {
  "main_breaker_closed": false, "tie_breaker_closed": false,
  "transfer_pump_running": false, "interlock_bypass": true,
  "feeder_trip": true, "bus_voltage_kv": 0.0
}
```

- And `/alarms`:

```json
{
  "id": "RLY104-PHASE-SLIP",
  "severity": "CRIT",
  "message": "52-T phase-slip trip asserted - TOKEN HTB{104_stale_handoff_tripped_52t_7af9eecb0051aa2fef9140cc3db5394e}"
}
```

## Key lessons

- **IEC-104 (and ICS protocols generally) have no built-in authentication.** Anything layered on top - like this challenge's "maintenance proof" handoff - is bespoke, application-level logic, and its failure modes have to be reasoned about on their own terms, not assumed to behave like TLS/HMAC would.
- **A changed error message is a real signal, not noise - but verify what it actually means before chasing it.** "Stale...accepted" looked at first like it could mean three different things (genuine crypto-adjacent partial validity, a duplicate-submission tag, or a fuzzy/prefix-match bug). I designed a specific control test for each theory (repeat a *fresh* random value; flip single bits of the known value) before trusting any interpretation, and that's what actually found the right one.
- **A pcap that establishes protocol *format* doesn't necessarily establish live *addressing*.** The demo session's IOA 1101/1201 mapping (breaker/pump) did not match the live RTU's real IOA assignments (interlock-bypass/tie-breaker) - I had to verify each command's effect against real state deltas rather than trust the capture's semantics.
- **Recognize infrastructure boundaries even under CTF pressure.** Both given ports sat in the Kubernetes NodePort range, meaning other competitors' instances almost certainly share the same host space - so I treated "the two ports on the instance card" as the actual scope of authorization, not "the whole host."
- **A real dead end is worth saying out loud, not papering over.** I told the operator plainly when I'd exhausted every idea I had from the wire alone, rather than continuing to guess silently - and it was that honest checkpoint, plus being told to keep trying, that led directly to re-examining the "stale" message instead of dismissing it.

## If asked to explain this live

- This was an IEC 60870-5-104 ICS challenge: a Frostline feeder RTU exposing a raw protocol port and a read-only HTTP HMI.
- The pcap taught me the protocol's byte format (a non-standard TypeId-104 "maintenance proof" frame layered on top of real IEC-104) but every control command against the live RTU was rejected with "no active handoff" until that proof was accepted.
- Replaying the pcap's exact proof bytes mostly failed with "bad proof rejected," but a small fraction of resends came back "stale maintenance proof accepted" and actually flipped `authorized` to true for about 30 seconds - a legacy/backward-compatible override that's probabilistic rather than deterministic, not a per-instance secret I'd need to crack.
- I ruled that out carefully first, by confirming a fresh random value never produces that response no matter how many times it's resent, and that single-bit-flipped variants of the known value always fail outright - so it really is an exact, recognized legacy credential, just an intermittently-honoured one.
- Once authorized, I swept candidate IOAs and found the real live control points didn't match the pcap's demo IOAs at all: 1101 turned out to be an interlock-bypass switch, and 1201 was the actual tie breaker.
- Setting the bypass and then closing the tie breaker while the transfer pump was still loaded and the bus was out of phase triggered a genuine phase-slip protection trip, and the resulting critical alarm carried the checkpoint token directly in its message.
