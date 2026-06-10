# TRex + iPerf3 + BGP Unified Web GUI — Product Requirements Document (PRD)

## 1. Product Overview

### 1.1 Product Name
**trex-web** — TRex + iPerf3 + BGP Unified Web Control Panel

### 1.2 Elevator Pitch
A single-page dark-mode web dashboard that unifies BGP route management, iPerf3 throughput testing, TRex traffic generation, and QoS verification on a dual-port 10G test server (UB-174), connected to Nexthop 4010 switches for data-center network validation.

### 1.3 Target Users
- **Network QA Engineers** — validate BGP peering, route propagation, and throughput between switches
- **SONiC/Nexthop Field Engineers** — verify switch configurations (QoS DSCP marking, VLAN, BGP) with real traffic
- **Lab Operators** — manage shared test hardware with time-shared port allocation

### 1.4 Deployment Target
| Item | Value |
|------|-------|
| Host | UB-174 (192.168.100.174) |
| OS | Ubuntu 24.04 |
| Web Port | `:8888` |
| Service | systemd `trex-web` (user: cunshen) |
| Code Path | `/opt/trex-web/` |
| GitHub | `github.com/mncif3/traffic_gen_trex_iperf_web_ui` |

### 1.5 Hardware
| Resource | Detail |
|----------|--------|
| NIC | Intel X710 4×10G (i40e driver) |
| Active Ports | Port 0 `enp8s0np0` → Switch 171 Eth513, Port 3 `enp11s0np1` → Switch 172 Eth513 |
| BGP Daemon | BIRD 2.x (dual instance in network namespaces) |
| Traffic Gen | TRex v3.06 (af_packet mode) |
| Throughput Test | iPerf3 (native, in network namespaces) |

---

## 2. Functional Requirements

### 2.1 BGP Neighbors Tab (`/` — default)
**Purpose**: Full lifecycle management of BGP peers with real-time route visibility.

| Feature | Detail |
|---------|--------|
| Add Neighbor | Peer IP (v4/v6), Peer AS, Local AS, Router-ID, Address Family (multi-select: IPv4/IPv6 Unicast), Description |
| Neighbor List | Card-based layout showing state badge, AS number, description, AF types, route counts (v4/v6) |
| State Display | `ESTABLISHED` / `CONNECTING` / `STOPPED` / `ERROR` — color-coded badges |
| Start/Stop | Per-neighbor BGP session control (hot-reload via `birdc configure`) |
| Delete | Stop session + remove config + delete from persistence |
| Route Editor | Advertise/Withdraw prefixes with next-hop per selected neighbor |
| Learned Routes | Table of v4/v6 prefixes learned from peer, with next-hop |
| Advertised Routes | Table of v4/v6 prefixes being advertised to peer |
| Auto-refresh | Polls `/api/bgp/status` every 5 seconds |
| Persistence | BGP state saved to `/opt/trex-web/bgp_state.json`, auto-loaded on restart |

**API Endpoints**:
- `GET  /api/bgp/status` — full BGP status with all neighbors + routes
- `GET  /api/bgp/neighbors` — neighbor list
- `POST /api/bgp/neighbors` — add neighbor
- `DELETE /api/bgp/neighbors/<ip>` — delete neighbor
- `POST /api/bgp/neighbors/<ip>/start` — start BGP session
- `POST /api/bgp/neighbors/<ip>/stop` — stop BGP session
- `GET  /api/bgp/neighbors/<ip>/routes` — learned + advertised routes per neighbor
- `POST /api/bgp/neighbors/<ip>/advertise` — advertise a prefix
- `POST /api/bgp/neighbors/<ip>/withdraw` — withdraw a prefix
- `GET  /api/bgp/routes` — all learned routes aggregated (for Traffic tab)

**Current Production State**: 4 neighbors Established:
- `10.0.0.3` (171-Eth513, AS65001) — v4 unicast, 6 prefixes
- `10.20.0.1` (172-Eth513, AS65002) — v4 unicast, 6 prefixes
- `2001:db8:513::1` (171-Eth513-IPv6, AS65001) — v6 unicast, 6 prefixes
- `2001:db8:514::1` (172-Eth513-IPv6, AS65002) — v6 unicast, 6 prefixes

---

### 2.2 Traffic Streams Tab
**Purpose**: Create and control TRex packet generation streams.

| Feature | Detail |
|---------|--------|
| Port Status | Live display of Port 0/1 link state, speed, IPs (v4/v6), MAC, mode ([iperf] badge) |
| Active Streams | List of configured stream blocks with key params |
| Namespace Panel | CRUD management of network namespaces (detailed in §2.3) |
| Create Stream | Full parameter form: Host, Port, Name, Protocol (UDP/TCP), Src/Dst IP, Dst MAC (manual/ARP/gateway modes), Src/Dst Port, Pkt Size, PPS, Bandwidth, DSCP, VLAN, PG ID, Latency toggle |
| BGP Route Source | "From BGP Route Table" — populates Dst IP from learned BGP routes |
| Stream Actions | Create, Start All, Stop, Reset |
| MAC Resolution | ARP (IPv4) and NDP (IPv6) for automatic next-hop MAC resolution |
| Gateway MAC | Uses default gateway's MAC for routed traffic |

**API Endpoints**:
- `GET    /api/ports?host=local` — port status
- `GET    /api/streams` — list stream blocks
- `POST   /api/streams` — create stream
- `DELETE /api/streams/<name>` — delete stream
- `POST   /api/start` — start traffic
- `POST   /api/stop` — stop traffic
- `POST   /api/reset` — reset TRex
- `GET    /api/trex_status?host=local` — TRex daemon status

---

### 2.3 Namespace Management (Traffic Tab sub-panel)
**Purpose**: Manage Linux network namespaces that isolate data-plane ports.

| Feature | Detail |
|---------|--------|
| List View | Card per namespace showing: name, description, physical interface, live interfaces (IPs v4/v6), live routes, config summary |
| Create | `+ New` button → form: Name, Description, Interface (dropdown of available X710 ports), IPv4/IPv6 CIDR, Gateway v4/v6, Static Routes (add/remove rows) |
| Edit | ✏️ button → same form pre-populated, name field disabled |
| Delete | 🗑 button → removes namespace config from `ns_config.json` |
| Port Scanning | Dropdown scans all 4 X710 ports (`enp8s0np0`–`enp11s0np1`), grays out ports already assigned |
| Live Discovery | Reads `ip netns exec <ns> ip addr` + `ip route` for real-time interface/route data |
| Persistence | `ns_config.json` — JSON file storing namespace configs |

**API Endpoints**:
- `GET    /api/namespaces` — list all namespaces (with live interface/route data)
- `POST   /api/namespaces` — create namespace
- `PUT    /api/namespaces/<name>` — update namespace
- `DELETE /api/namespaces/<name>` — delete namespace
- `GET    /api/namespaces/ports` — list available physical ports

**Current Production Namespaces**:
| Name | Port | IPv4 | IPv6 | Gateway | Switch |
|------|------|------|------|---------|--------|
| iperf_ns2 | enp8s0np0 | 10.0.0.2/31 | 2001:db8:513::2/64 | 10.0.0.3 | 171 Eth513 |
| iperf_ns | enp11s0np1 | 10.20.0.0/31 | 2001:db8:514::2/64 | 10.20.0.1 | 172 Eth513 |

---

### 2.4 Statistics Tab
**Purpose**: Real-time per-port traffic statistics and per-stream latency.

| Feature | Detail |
|---------|--------|
| Per-Port Stats | TX/RX packets, PPS, BPS, errors, loss percentage — auto-refresh every 1s |
| Per-Stream Latency | PG-level: avg/min/max/jitter in μs, dropped packets, out-of-order packets |
| Auto-poll | Starts on traffic start, stops on traffic stop |
| Timestamp | "Updated HH:MM:SS" refresh indicator |

**API Endpoints**:
- `GET /api/stats?host=local` — port stats + latency data

---

### 2.5 Hosts Tab
**Purpose**: Manage TRex server connections (primarily local, extensible for remote).

| Feature | Detail |
|---------|--------|
| Host List | Shows all registered TRex hosts with connection status (UP/DOWN badge) |
| Add Host | IP + Display Name |
| Delete Host | Remove non-local hosts |
| Stream Host Selector | Traffic tab's Host dropdown updated from this list |

**API Endpoints**:
- `GET    /api/hosts` — list hosts
- `POST   /api/hosts` — add host
- `DELETE /api/hosts/<name>` — delete host

---

### 2.6 iPerf3 Tab
**Purpose**: Create and run iPerf3 throughput tests between namespace-isolated ports through the switch.

| Feature | Detail |
|---------|--------|
| Create Stream | Protocol (TCP/UDP), Port, Duration, Interval, Parallel, Src IP (dropdown from namespace IPs), Target IP, Bandwidth, Pkt Size, DSCP, Window, MSS, Omit, Connect Timeout, Bidir/Reverse/ZeroCopy toggles |
| Stream List | Per-stream cards with: ID, status (RUNNING/IDLE badge), protocol, parameters, last result summary |
| Batch Operations | Select-all checkbox, Start Selected, Stop Selected |
| Live Results | Inline result panel showing: bitrate, transferred MB, lost%, jitter, retransmits, duration, per-interval breakdown |
| Edit Stream | ✎ button → modal with same form fields |
| Auto-poll | Status polling every 1s during active test |
| Parameter Guide | Reference table of all iperf3 CLI flags with descriptions and examples |

**Architecture**: Server listens in the target namespace on all addresses. Client runs in the source namespace, connects to server IP. Traffic hairpins through the switch (never touches management port).

**API Endpoints**:
- `GET  /api/iperf/interfaces` — namespace IPs for Src IP dropdown
- `GET  /api/iperf/streams` — list streams
- `POST /api/iperf/streams` — create stream
- `PUT  /api/iperf/streams/<sid>` — update stream
- `DELETE /api/iperf/streams/<sid>` — delete stream
- `POST /api/iperf/streams/batch/start` — batch start
- `POST /api/iperf/streams/<sid>/start` — start single stream
- `POST /api/iperf/streams/<sid>/stop` — stop single stream
- `GET  /api/iperf/streams/<sid>/status` — poll status + live results

---

### 2.7 QoS Test Tab
**Purpose**: Verify DSCP-based QoS queue mapping on Nexthop switches.

| Feature | Detail |
|---------|--------|
| Embedded Page | iframe loading `/qos` (separate `qos_test.html`) |
| DSCP Mapping | Table mapping DSCP values (0-63) to switch queue IDs |
| Switch Selector | Dropdown of available switches |
| Run Test | Send iperf3 traffic with specific DSCP, monitor switch queue counters |
| Counter Display | Per-queue packet/byte counters before/after test |
| Clear Counters | Reset switch counters before test |

**API Endpoints**:
- `GET  /api/qos/mapping` — DSCP-to-queue mapping
- `POST /api/qos/run` — run QoS test (iperf3 + counter read)
- `GET  /api/qos/switches` — list switches
- `POST /api/qos/clear_counters` — clear switch counters

---

## 3. Architecture

### 3.1 System Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   UB-174 (192.168.100.174)               │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │              trex-web (Flask :8888)               │   │
│  │  ┌──────────┬──────────┬──────────┬──────────┐   │   │
│  │  │   BGP    │  iPerf3  │   TRex   │   QoS    │   │   │
│  │  │  Module  │  Module  │  Module  │  Module  │   │   │
│  │  └────┬─────┴────┬─────┴────┬─────┴────┬─────┘   │   │
│  └───────┼──────────┼──────────┼──────────┼─────────┘   │
│          │          │          │          │              │
│  ┌───────┴──┐  ┌───┴────┐  ┌──┴─────┐  ┌─┴──────────┐  │
│  │ BIRD 2.x │  │ iperf3 │  │  TRex  │  │SNMP/SSH to │  │
│  │  (ns2)   │  │ server │  │af_pkt  │  │  Switches  │  │
│  │  (ns)    │  │+client │  │        │  │            │  │
│  └────┬─────┘  └───┬────┘  └───┬────┘  └────────────┘  │
│       │             │           │                        │
│  ┌────┴─────────────┴───────────┴───────────────────┐   │
│  │           Network Namespaces                      │   │
│  │  iperf_ns2 (enp8s0np0) ←→ Switch 171 Eth513      │   │
│  │  iperf_ns  (enp11s0np1) ←→ Switch 172 Eth513     │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 3.2 BIRD Architecture (BGP)

```
┌─────────────┐                    ┌─────────────┐
│  iperf_ns2   │                    │  iperf_ns    │
│  10.0.0.2   │                    │ 10.20.0.0   │
│             │                    │             │
│  BIRD inst  │◄──── BGP ────────►│  BIRD inst  │
│  /tmp/bird/ │   (mgmt net)       │ /tmp/bird/  │
│  ns2.ctl    │                    │  ns.ctl     │
│             │                    │             │
│  Peers:     │                    │  Peers:     │
│  10.0.0.3   │──► Switch 171      │ 10.20.0.1  │──► Switch 172
│  2001:db8:  │──► Switch 171(v6)  │ 2001:db8:  │──► Switch 172(v6)
│  513::1     │                    │  514::1     │
└─────────────┘                    └─────────────┘
```

- BIRD 2.x runs inside data-plane namespaces (NOT management namespace)
- BGP sessions established over management network (192.168.100.x)
- Config hot-reload via `birdc configure` (no restart needed)
- Route advertisement uses `static blackhole` + `export filter` pattern with `next hop self`
- BGP state decoupled from data-plane port mode — always operational

### 3.3 Port Time-Sharing

TRex and iPerf3 cannot run simultaneously (mutually exclusive port ownership).

```
Mode: iPerf3
  enp8s0np0 → iperf_ns2   enp11s0np1 → iperf_ns
  (separate namespaces = traffic hairpins through switch)

Mode: TRex
  enp8s0np0 + enp11s0np1 → trex_ns
  (single namespace = TRex sees both ports)
```

Switching via `sudo netns-mode.sh {iperf|trex}`:
1. Kill running iperf3/TRex processes
2. Move NICs back to root namespace
3. Delete old namespaces
4. Create new namespaces and move NICs
5. Assign IPs and bring interfaces up

TRex uses `af_packet` PMD (kernel driver) — no DPDK/vfio-pci rebind needed.

---

## 4. Non-Functional Requirements

### 4.1 UI/UX
| Requirement | Detail |
|-------------|--------|
| Theme | Dark mode: `#0f1119` bg, `#161822` cards, `#4f8cff` accent |
| Layout | Single-page app, 6 tabs, no page reloads |
| Responsiveness | Two-column grid, collapses to single column on < 1000px viewport |
| Real-time | Auto-refresh: BGP every 5s, Stats every 1s, iPerf3 status every 1s |
| Compatibility | Modern browsers (Chrome/Firefox/Edge), vanilla JS (no framework dependency) |

### 4.2 Performance
- BGP status API: < 2s (includes `birdc show protocols` + `birdc show route` calls)
- iPerf3 results: real-time JSON parsing
- TRex stats: < 500ms per poll

### 4.3 Reliability
- BGP state persistence across service restarts
- Namespace config persistence in `ns_config.json`
- BIRD hot-reload — no session flap on config changes
- Graceful handling of TRex not running (Port Status shows link info only)

### 4.4 Security
- Runs on internal management network (192.168.100.0/24)
- No authentication (lab/internal use)
- Passwordless sudo for `ip netns`, `bird`, `birdc` commands
- Management port (192.168.100.x) excluded from data-plane traffic

---

## 5. Technical Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3 + Flask |
| Frontend | Vanilla JavaScript (no framework), single HTML file |
| BGP Daemon | BIRD 2.x |
| Traffic Generator | TRex v3.06 (STL Python API) |
| Throughput Test | iPerf3 |
| Packet Crafting | Scapy (ARP/NDP resolution) |
| Process Management | systemd |
| Configuration | JSON files (`bgp_state.json`, `ns_config.json`) |

---

## 6. File Manifest

| File | Lines | Purpose |
|------|-------|---------|
| `app.py` | 1,626 | Flask backend — all API routes + BGP/iPerf3/TRex/QoS/Namespace modules |
| `templates/index.html` | 1,445 | Single-page frontend — HTML + CSS + vanilla JS |
| `templates/qos_test.html` | 222 | QoS Test standalone page (iframe-embedded) |
| `netns-mode.sh` | 105 | Namespace mode switcher (iperf ↔ trex) |
| `ns_config.json` | 24 | Namespace configuration persistence |
| `trex_cfg_afpacket.yaml` | — | TRex af_packet configuration |
| `BIRD_ARCHITECTURE.md` | 102 | Architecture documentation |

---

## 7. Known Constraints & Trade-offs

| Item | Detail |
|------|--------|
| TRex Throughput | af_packet mode limits TRex to a few Gbps (not 10G line rate); acceptable for functional/QoS testing |
| iPerf3 Throughput | ~9.4 Gbps achieved (native kernel datapath) |
| Mutually Exclusive | TRex and iPerf3 cannot run concurrently — ports are time-shared |
| No Authentication | Internal lab use only, no auth layer |
| BIRD Only | ExaBGP removed in v2; BIRD 2.x required (Ubuntu 24.04 default) |
| No SSH to 174 | Requires console/IPMI for initial setup |
| Vanilla JS | No Vue/React — single-file HTML for deployment simplicity |

---

## 8. Version History

| Version | Key Changes |
|---------|------------|
| v1 | Initial: ExaBGP + TRex (DPDK) + Flask web GUI |
| v2 | BIRD replaces ExaBGP; TRex af_packet mode; netns-mode.sh for port time-sharing |
| v2.1 | Data-plane BGP Established + iPerf3 verified 9.39 Gbps |
| v3 | Namespace dual-BIRD with persistence; Bug 1 (Src IP dropdown) + Bug 2 (Server bind) fixes |
| v4 | IPv6 BGP support, 4 neighbors Established, Namespace management panel in Traffic tab |
| v5 | Port Status shows namespace interface info when TRex not running; bug fixes (ternary syntax, editNamespace→showNsForm) |

---

## 9. API Reference Summary

### BGP Routes
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/bgp/status` | Full BGP status |
| GET | `/api/bgp/neighbors` | List neighbors |
| POST | `/api/bgp/neighbors` | Add neighbor |
| DELETE | `/api/bgp/neighbors/<ip>` | Delete neighbor |
| POST | `/api/bgp/neighbors/<ip>/start` | Start session |
| POST | `/api/bgp/neighbors/<ip>/stop` | Stop session |
| GET | `/api/bgp/neighbors/<ip>/routes` | Neighbor routes |
| POST | `/api/bgp/neighbors/<ip>/advertise` | Advertise prefix |
| POST | `/api/bgp/neighbors/<ip>/withdraw` | Withdraw prefix |
| GET | `/api/bgp/routes` | All learned routes |

### iPerf3 Routes
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/iperf/interfaces` | Namespace IPs |
| GET | `/api/iperf/streams` | List streams |
| POST | `/api/iperf/streams` | Create stream |
| PUT | `/api/iperf/streams/<sid>` | Update stream |
| DELETE | `/api/iperf/streams/<sid>` | Delete stream |
| POST | `/api/iperf/streams/batch/start` | Batch start |
| POST | `/api/iperf/streams/<sid>/start` | Start stream |
| POST | `/api/iperf/streams/<sid>/stop` | Stop stream |
| GET | `/api/iperf/streams/<sid>/status` | Stream status |

### Namespace Routes
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/namespaces` | List namespaces |
| POST | `/api/namespaces` | Create namespace |
| PUT | `/api/namespaces/<name>` | Update namespace |
| DELETE | `/api/namespaces/<name>` | Delete namespace |
| GET | `/api/namespaces/ports` | Available ports |

### TRex Routes
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/ports` | Port status |
| GET | `/api/streams` | List streams |
| POST | `/api/streams` | Create stream |
| DELETE | `/api/streams/<name>` | Delete stream |
| POST | `/api/start` | Start traffic |
| POST | `/api/stop` | Stop traffic |
| POST | `/api/reset` | Reset TRex |
| GET | `/api/stats` | Traffic stats |
| GET | `/api/trex_status` | TRex daemon status |
| GET | `/api/hosts` | List hosts |
| POST | `/api/hosts` | Add host |
| DELETE | `/api/hosts/<name>` | Delete host |

### QoS Routes
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/qos/mapping` | DSCP mapping |
| POST | `/api/qos/run` | Run QoS test |
| GET | `/api/qos/switches` | Switch list |
| POST | `/api/qos/clear_counters` | Clear counters |

### Frontend
| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Main SPA (index.html) |
| GET | `/qos` | QoS test page (qos_test.html) |

---

## 10. Deployment & Operations

### 10.1 Service Control
```bash
sudo systemctl [start|stop|restart|status] trex-web
sudo journalctl -u trex-web --no-pager -n 50  # logs
```

### 10.2 Port Mode Switching
```bash
sudo /opt/trex-web/netns-mode.sh iperf     # iPerf3 + QoS mode
sudo /opt/trex-web/netns-mode.sh trex      # TRex traffic mode
sudo /opt/trex-web/netns-mode.sh status    # current mode
```

### 10.3 Manual BIRD Diagnostics
```bash
sudo ip netns exec iperf_ns2 birdc -s /tmp/bird/ns2.ctl show protocols
sudo ip netns exec iperf_ns birdc -s /tmp/bird/ns.ctl show protocols
```

### 10.4 BGP Neighbor Recovery
If neighbors are lost after restart:
```bash
curl -s -X POST http://127.0.0.1:8888/api/bgp/neighbors \
  -H 'Content-Type: application/json' \
  -d '{"ip":"10.0.0.3","asn":65001,"description":"171-Eth513"}'
curl -s -X POST http://127.0.0.1:8888/api/bgp/neighbors/10.0.0.3/start
```

---

*Document version: 1.0 | Generated: 2026-06-11 | Author: Hermes Agent*
