# trex-web — BIRD-only BGP + namespace-shared TRex/iPerf3

This delivers the three decisions you made: BGP runs on BIRD only (ExaBGP removed), TRex reuses the same kernel-namespace data ports as iPerf3 (no DPDK rebind), and the two physical 10G ports are time-shared between TRex and iPerf3 (never concurrent). The earlier iPerf3 Bug 1 and Bug 2 fixes are folded into the same patch.

## Is your plan feasible? Yes — here is how

The key enabler is that TRex does not have to take the NICs via `vfio-pci`/DPDK. TRex can run over kernel interfaces with its `af_packet` PMD (`--vdev=net_af_packet`). That means:

* Both 10G ports stay on the `i40e` kernel driver, inside network namespaces, all the time.
* There is never a driver rebind. Switching between TRex and iPerf3 only moves the two NICs between namespaces.
* All traffic leaves the data ports only — it never touches the management port, which was your main concern.

The one honest trade-off: af_packet is a software datapath, so TRex will do a few Gbps, not 10G line rate. iPerf3 still runs natively in the namespace and keeps its ~9.4 Gbps. For QoS and functional verification this is fine; if you ever need TRex at line rate you would have to switch that port to `vfio-pci`, which is mutually exclusive with the namespace model. That mutual exclusivity is exactly why TRex and iPerf3 are time-shared.

## Hardware and addressing assumed

| Port | netdev | PCI | Switch | IPERF mode ns / IP | TREX mode ns / IP |
|------|--------|-----|--------|--------------------|-------------------|
| Port 0 | enp8s0np0 | 08:00.0 | 171 Eth513 | `iperf_ns2` / 10.0.0.0 | `trex_ns` / 10.0.0.0 |
| Port 3 | enp11s0np1 | 0b:00.0 | 172 Eth513 | `iperf_ns` / 10.0.0.2 | `trex_ns` / 10.0.0.2 |

IPERF mode keeps the two ends in two separate namespaces (so traffic hairpins through the switch). TREX mode puts both ports in one `trex_ns` namespace so a single TRex process can see both. The switch-side /31 peers are 10.0.0.1 (171) and 10.0.0.3 (172). Adjust the device names and IPs at the top of `netns-mode.sh` if the box differs.

## What changed in `app.py`

One file, validated to parse and to apply cleanly as a patch.

### BGP: ExaBGP to BIRD (API contract unchanged)
The whole ExaBGP block (log parser, config builder, process control, CLI-pipe advertise/withdraw) is replaced with a BIRD 2.x implementation. The HTTP routes and JSON shapes are identical, so `index.html` needs no changes.

* Header constants `EXABGP_*` to `BIRD_BIN` / `BIRDC` / `BIRD_CONF` / `BIRD_SOCK`; `bgp_process` global removed.
* `_build_bird_config()` renders `bird.conf` from `bgp_local_config` + `bgp_neighbors`. Each active neighbor becomes a `protocol bgp peer_<ip>` with `import all`. Per-neighbor advertised prefixes become a `protocol static static4_/static6_<peer>` (blackhole routes) and are exported only to that peer via `export where proto = "static4_<peer>"` plus `next hop self`.
* `_start_bird()` writes the config and either starts `bird` or runs `birdc configure` to hot-reload; `_stop_bird()` uses `birdc down`. `_check_bgp_running()` uses `pgrep -x bird`.
* `_parse_bird_live()` (drop-in for the old `_parse_exabgp_log()`) reads `birdc show protocols` for session state and `birdc show route protocol <peer> all` for learned prefixes.
* Advertise/withdraw no longer pipe to `exabgp-cli`; they update the in-memory advertised list, re-render the config, and `birdc configure`. Advertise rolls back the in-memory change if the reconfigure fails.

BGP peers over the management network exactly as ExaBGP did, so it is independent of which data-port mode is active. The "use BIRD because it natively integrates with TRex" goal is set up structurally here; wiring BIRD-learned routes into the TRex datapath is a clean follow-up, not part of this patch.

### Bug 1: empty Src IP dropdown
`_get_interfaces()` now runs `sudo ip netns exec <ns> ip -j addr` for `iperf_ns2` then `iperf_ns`, filters loopback and the `192.168.100.x` mgmt subnet, and returns `[{"name":"iperf_ns2","ipv4":["10.0.0.2"],...}, {"name":"iperf_ns","ipv4":["10.0.0.0"],...}]` — the shape your frontend expects.

### Bug 2: "Server failed to start"
`_build_iperf_cmd(..., 'server')` no longer appends `-B <target_ip>`. The deployed code already wrapped the server in `ip netns exec`; the real cause was the bind, which makes `iperf3 -s` exit 1 when the address is not assignable. The server now listens on all namespace addresses (matching the proven `/api/qos/run` path) and the client still targets the server IP with `-c`.

## Files in this handoff

* `app.py` — drop-in replacement for `/opt/trex-web/app.py` (BIRD + Bug 1/Bug 2).
* `trex-web-bird-afpacket.patch` — unified diff, `git apply -p1` or `patch -p1` against `/opt/trex-web/app.py`.
* `trex_cfg_afpacket.yaml` — TRex config using af_packet on the two kernel ports; install as `/etc/trex_cfg_afpacket.yaml`.
* `netns-mode.sh` — sets up IPERF or TREX namespaces and switches between them.

## Deploy

Prerequisites inside the container: `apt-get install -y bird2`, and the `trex-web` process user must be able to run `sudo ip netns ...`, `sudo bird`, and `sudo birdc` non-interactively (the QoS path already relies on passwordless sudo, so this should already hold).

```bash
# 1. back up
docker exec trex-web cp /opt/trex-web/app.py /opt/trex-web/app.py.bak

# 2. drop in the fixed app (simplest), or apply the patch
docker cp app.py trex-web:/opt/trex-web/app.py
docker cp trex_cfg_afpacket.yaml trex-web:/etc/trex_cfg_afpacket.yaml
docker cp netns-mode.sh trex-web:/opt/trex-web/netns-mode.sh
docker exec trex-web chmod +x /opt/trex-web/netns-mode.sh

# 3. restart and watch it come up on :8888
docker restart trex-web
docker logs -f trex-web
```

Patch alternative: `docker cp trex-web-bird-afpacket.patch trex-web:/tmp/ && docker exec -it trex-web sh -c 'cd / && patch -p1 < /tmp/trex-web-bird-afpacket.patch'`.

## Operate (time-share the two ports)

```bash
# iPerf3 / QoS session
sudo /opt/trex-web/netns-mode.sh iperf
#   -> use the iPerf3 and QoS Test tabs

# TRex session
sudo /opt/trex-web/netns-mode.sh trex
sudo ip netns exec trex_ns /opt/trex/t-rex-64 -i --cfg /etc/trex_cfg_afpacket.yaml
#   -> then use the Traffic Streams / Statistics tabs

sudo /opt/trex-web/netns-mode.sh status     # show current namespace IPs
```

Switching modes bounces the two links for a few seconds and ends any in-flight test. Do not run TRex and iPerf3 at the same time — that is the accepted constraint.

## Verify

1. `sudo netns-mode.sh iperf`, then `curl -s http://192.168.100.174:8888/api/iperf/interfaces` returns a non-empty `interfaces` array (Bug 1).
2. Create an iPerf3 stream (Src IP = the `iperf_ns2` address, target = the `iperf_ns` address), Start — it returns success, not "Server failed to start" (Bug 2). Watch the 171/172 Eth513 queue counters move in the QoS tab.
3. BGP tab: add a neighbor (171/172 mgmt IP), Start, confirm it reaches Established; verify with `docker exec trex-web birdc -s /run/bird/bird.ctl show protocols`. Advertise a prefix and confirm with `birdc ... show route export <peer>`.
4. `sudo netns-mode.sh trex` then launch TRex; the Traffic and Statistics tabs connect over the local STL API and traffic flows over the data ports (a few Gbps via af_packet).

## Open items / caveats

* BIRD must be version 2.x (Ubuntu 24.04 default). The generated config uses 2.x channel syntax (`ipv4 { ... }`), which is not compatible with BIRD 1.x.
* af_packet throughput is well below 10G by design; this is the cost of keeping TRex on the kernel/namespace model alongside iPerf3.
* The `static ... blackhole` + `next hop self` pattern is the standard way to originate prefixes from BIRD without a real FIB route; it is purely for advertisement and does not blackhole live data, since the data path is the switch, not this host's FIB.
* Bug 3 (no SSH to 174) is unchanged — it is a credentials/console issue, not code. You still need console/IPMI or an alternate login to run the `docker cp` step.
