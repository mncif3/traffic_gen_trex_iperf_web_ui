#!/usr/bin/env python3
"""
TRex + BGP Unified Web GUI v4 — Multi-neighbor BGP, per-neighbor route management
"""
import sys, os, json, time, threading, subprocess, signal, re, socket, struct
sys.path.insert(0, '/opt/trex/automation/trex_control_plane/interactive')

from flask import Flask, jsonify, request, send_from_directory
from trex.stl.api import (STLClient, STLStream, STLTXCont, STLPktBuilder,
                           STLFlowLatencyStats)
from scapy.all import (Ether, IP, IPv6, UDP, TCP, Raw, Dot1Q,
                        ARP, arping, get_if_hwaddr)
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__, static_folder='static', template_folder='templates')

# ─── Global State ───
bgp_process = None
bgp_running = False
bgp_local_config = {'local_as': 65000, 'router_id': '192.168.100.174'}
bgp_neighbors = {}  # {ip: {asn, description, active, state, prefixes_v4, prefixes_v6, advertised_v4, advertised_v6}}

EXABGP_LOG = '/tmp/exabgp_run.log'
EXABGP_CONF = '/tmp/exabgp_running.conf'
EXABGP_BIN = '/home/cunshen/.local/bin/exabgp'
EXABGP_CLI = '/home/cunshen/.local/bin/exabgp-cli'

# TRex hosts
trex_hosts = {
    'local': {'ip': '127.0.0.1', 'name': 'UB-174 (local)', 'client': None, 'connected': False}
}
current_streams = {}

# ═══════════════════ TRex Client ═══════════════════
def get_trex_client(host_name='local'):
    h = trex_hosts.get(host_name)
    if not h:
        return None
    if h['client'] is None:
        try:
            c = STLClient(server=h['ip'])
            c.connect()
            c.acquire(ports=[0, 1], force=True)
            h['client'] = c
            h['connected'] = True
        except Exception as e:
            h['connected'] = False
            return None
    return h['client']

# ═══════════════════ ARP/NDP ═══════════════════
def is_ipv6(ip):
    return ':' in ip

def arp_resolve(ip, interface=None):
    if is_ipv6(ip):
        return ndp_resolve(ip, interface)
    try:
        ans, _ = arping(ip, timeout=2, verbose=False)
        if ans:
            for snd, rcv in ans:
                return rcv.src
    except:
        pass
    try:
        with open('/proc/net/arp') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    return parts[3]
    except:
        pass
    return None

def ndp_resolve(ip, interface=None):
    try:
        result = subprocess.run(['ip', '-6', 'neigh', 'show', ip],
                                capture_output=True, text=True, timeout=3)
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts[0] == ip and 'lladdr' in line:
                idx = parts.index('lladdr')
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except:
        pass
    try:
        result = subprocess.run(['ip', '-6', 'neigh'], capture_output=True, text=True, timeout=3)
        for line in result.stdout.splitlines():
            if ip in line and 'lladdr' in line:
                parts = line.split()
                idx = parts.index('lladdr')
                if idx + 1 < len(parts):
                    return parts[idx + 1]
    except:
        pass
    return None

def get_gateway_mac(interface='eth0'):
    try:
        routes = open('/proc/net/route').readlines()
        for line in routes[1:]:
            parts = line.split()
            if parts[1] == '00000000':
                gw = socket.inet_ntoa(struct.pack('<I', int(parts[2], 16)))
                return arp_resolve(gw)
    except:
        pass
    return None

# ═══════════════════ Bandwidth/PPS ═══════════════════
def bandwidth_to_pps(bw_mbps, pkt_size=64):
    overhead = 20
    return int((bw_mbps * 1e6) / ((pkt_size + overhead) * 8))

def pps_to_bandwidth(pps, pkt_size=64):
    overhead = 20
    return round((pps * (pkt_size + overhead) * 8) / 1e6, 2)

# ═══════════════════ BGP: Multi-Neighbor Log Parser ═══════════════════

RE_PEER_OUTGOING = re.compile(r'outgoing-(\d+)\s+attempting connection to (\S+):179')
RE_PEER_OPEN = re.compile(r'(?:peer|outgoing)-(\d+)\s+<< OPEN version=\d+ asn=(\d+)')
RE_PEER_EOR_ALL = re.compile(r'peer-(\d+)\s+>> all EOR')
RE_PEER_UPDATE_NLRI_IP = re.compile(
    r'peer-(\d+)\s+UPDATE #\d+\s+nlri\s+\(\s*\d+\)\s+'
    r'([0-9a-fA-F:./]+)\s+next-hop\s+(\S+)'
)
RE_PEER_UPDATE_EOR = re.compile(r'peer-(\d+)\s+UPDATE #\d+\s+nlri.*eor\s')
RE_PEER_KEEPALIVE = re.compile(r'peer-(\d+).*KEEPALIVE')

def _parse_exabgp_log():
    """Parse ExaBGP log for multi-neighbor state and per-peer routes.

    Returns:
        peer_map: {ip: {state, asn, prefixes_v4, prefixes_v6}}
    """
    peer_map = {}  # {peer_num: ip}
    peer_state = {}  # {peer_num: state}
    peer_asn = {}  # {peer_num: asn}
    peer_routes_v4 = {}  # {peer_num: [{prefix, next_hop}]}
    peer_routes_v6 = {}

    try:
        with open(EXABGP_LOG) as f:
            content = f.read()
    except:
        content = ''

    lines = content.splitlines()

    for line in lines:
        # Map outgoing-N to IP
        m = RE_PEER_OUTGOING.search(line)
        if m:
            peer_num, ip = int(m.group(1)), m.group(2)
            peer_map[peer_num] = ip
            if ip not in peer_state:
                peer_state[ip] = 'connecting'

        # Peer OPEN → established
        m = RE_PEER_OPEN.search(line)
        if m:
            pn = int(m.group(1))
            peer_asn[pn] = int(m.group(2))
            if pn in peer_map:
                peer_state[peer_map[pn]] = 'established'

        # All EOR sent → fully up
        m = RE_PEER_EOR_ALL.search(line)
        if m:
            pn = int(m.group(1))
            if pn in peer_map:
                peer_state[peer_map[pn]] = 'up'

        # Keepalive confirms liveliness
        m = RE_PEER_KEEPALIVE.search(line)
        if m:
            pn = int(m.group(1))
            if pn in peer_map and peer_state.get(peer_map[pn], '') in ('', 'connecting'):
                peer_state[peer_map[pn]] = 'up'

        # EOR in update → skip
        if RE_PEER_UPDATE_EOR.search(line):
            continue

        # NLRI routes
        m = RE_PEER_UPDATE_NLRI_IP.search(line)
        if m:
            pn = int(m.group(1))
            prefix = m.group(2)
            next_hop = m.group(3)
            is_v6 = ':' in prefix
            if is_v6:
                peer_routes_v6.setdefault(pn, []).append({'prefix': prefix, 'next_hop': next_hop})
            else:
                peer_routes_v4.setdefault(pn, []).append({'prefix': prefix, 'next_hop': next_hop})

    # Deduplicate routes per peer
    for routes_dict in (peer_routes_v4, peer_routes_v6):
        for pn in list(routes_dict.keys()):
            seen = set()
            deduped = []
            for r in routes_dict[pn]:
                if r['prefix'] not in seen:
                    seen.add(r['prefix'])
                    deduped.append(r)
            routes_dict[pn] = deduped

    # Build result keyed by IP
    result = {}
    for ip, nbr in bgp_neighbors.items():
        # Find which peer_num maps to this IP
        pn = None
        for num, pip in peer_map.items():
            if pip == ip:
                pn = num
                break

        state = peer_state.get(ip, nbr.get('state', 'unknown'))
        # Default: if BGP is running and we have a peer_num, assume 'connecting' if no state yet
        if state == 'unknown' and pn:
            state = 'connecting'

        result[ip] = {
            'state': state,
            'asn': peer_asn.get(pn, nbr.get('asn', 0)),
            'prefixes_v4': peer_routes_v4.get(pn, []),
            'prefixes_v6': peer_routes_v6.get(pn, []),
        }

    # Also detect any new peers from log that aren't in our config
    for pn, ip in peer_map.items():
        if ip not in result:
            result[ip] = {
                'state': peer_state.get(ip, 'up'),
                'asn': peer_asn.get(pn, 0),
                'prefixes_v4': peer_routes_v4.get(pn, []),
                'prefixes_v6': peer_routes_v6.get(pn, []),
            }

    return result

# ═══════════════════ BGP: Config Builder ═══════════════════

def _get_local_ipv6():
    """Find a global unicast IPv6 address on this host."""
    try:
        result = subprocess.run(['ip', '-6', 'addr', 'show', 'scope', 'global'],
                                capture_output=True, text=True, timeout=3)
        for line in result.stdout.splitlines():
            m = re.search(r'inet6\s+([0-9a-f:]+)/\d+', line)
            if m and not m.group(1).startswith('fe80'):
                return m.group(1)
    except:
        pass
    return '::1'

def _build_exabgp_config():
    """Build ExaBGP config file from active neighbors."""
    config = []
    for ip, nbr in bgp_neighbors.items():
        if not nbr.get('active', True):
            continue  # skip stopped neighbors

        is_v6 = ':' in ip
        local_addr = bgp_local_config['router_id']
        if is_v6:
            local_addr = _get_local_ipv6()

        # Determine AF: if IPv6 peer, prefer ipv6; if IPv4, prefer both
        af_list = nbr.get('af_types', [])
        if not af_list:
            af_list = ['ipv4 unicast', 'ipv6 unicast'] if not is_v6 else ['ipv6 unicast', 'ipv4 unicast']

        families = ';\n    '.join(af_list) + ';'

        config.append(f"""neighbor {ip} {{
    router-id {bgp_local_config['router_id']};
    local-as {bgp_local_config['local_as']};
    local-address {local_addr};
    peer-as {nbr['asn']};
    hold-time 30;
    family {{ {families}; }}
    api services {{ receive-routes; }}
}}""")

    with open(EXABGP_CONF, 'w') as f:
        f.write('\n'.join(config))

    return config

def _start_exabgp():
    """Start or restart ExaBGP process."""
    global bgp_process, bgp_running

    # Build config
    config = _build_exabgp_config()
    if not config:
        return False, "No active neighbors to start"

    # Kill existing process if running
    _stop_exabgp()
    time.sleep(1)

    try:
        # Use shell redirect for reliable log output
        cmd = f"{EXABGP_BIN} {EXABGP_CONF} --debug > {EXABGP_LOG} 2>&1"
        bgp_process = subprocess.Popen(
            cmd, shell=True, preexec_fn=os.setsid
        )
        time.sleep(4)
        # ExaBGP daemonizes: parent exits, child keeps running
        # Check pgrep to confirm the daemon is alive
        try:
            result = subprocess.run(['pgrep', '-f', 'exabgp'],
                                    capture_output=True, text=True, timeout=3)
            if result.stdout.strip():
                bgp_running = True
                return True, "BGP started"
        except:
            pass

        return False, "ExaBGP did not start"
    except Exception as e:
        bgp_running = False
        return False, str(e)

def _stop_exabgp():
    """Stop ExaBGP process if running."""
    global bgp_process, bgp_running
    if bgp_process:
        try:
            os.killpg(os.getpgid(bgp_process.pid), signal.SIGTERM)
        except:
            try:
                bgp_process.terminate()
            except:
                pass
        bgp_process = None
    bgp_running = False

def _check_bgp_running():
    """Check if ExaBGP is actually running."""
    global bgp_running
    try:
        result = subprocess.run(['pgrep', '-f', 'exabgp'],
                                capture_output=True, text=True, timeout=3)
        bgp_running = bool(result.stdout.strip())
    except:
        bgp_running = bgp_process is not None and bgp_process.poll() is None
    return bgp_running

# ═══════════════════ BGP: API Endpoints ═══════════════════

@app.route('/api/bgp/status')
def bgp_status():
    """Overall BGP status with all neighbors."""
    _check_bgp_running()

    # Parse log for live state
    live_peers = _parse_exabgp_log()

    # Merge live state into our neighbor config
    neighbors = {}
    for ip, nbr in bgp_neighbors.items():
        live = live_peers.get(ip, {})
        state = live.get('state', nbr.get('state', 'configured'))
        # If BGP not running, mark all as stopped
        if not bgp_running and state not in ('stopped', 'configured'):
            state = 'stopped'

        neighbors[ip] = {
            'ip': ip,
            'asn': nbr.get('asn', 0),
            'description': nbr.get('description', ''),
            'active': nbr.get('active', True),
            'state': state,
            'prefixes_v4': live.get('prefixes_v4', nbr.get('learned_v4', [])),
            'prefixes_v6': live.get('prefixes_v6', nbr.get('learned_v6', [])),
            'advertised_v4': nbr.get('advertised_v4', []),
            'advertised_v6': nbr.get('advertised_v6', []),
            'af_types': nbr.get('af_types', ['ipv4 unicast', 'ipv6 unicast']),
        }

        # Update learned routes in memory
        if live.get('prefixes_v4'):
            nbr['learned_v4'] = live['prefixes_v4']
        if live.get('prefixes_v6'):
            nbr['learned_v6'] = live['prefixes_v6']
        nbr['state'] = state

    # Also include live peers not in config — and auto-add them to bgp_neighbors
    for ip, live in live_peers.items():
        if ip not in neighbors:
            neighbors[ip] = {
                'ip': ip,
                'asn': live.get('asn', 0),
                'description': '(auto-detected)',
                'active': True,
                'state': live.get('state', 'up'),
                'prefixes_v4': live.get('prefixes_v4', []),
                'prefixes_v6': live.get('prefixes_v6', []),
                'advertised_v4': [],
                'advertised_v6': [],
                'af_types': ['ipv4 unicast', 'ipv6 unicast'],
            }
            # Auto-add to bgp_neighbors so config builder includes it on restart
            if ip not in bgp_neighbors:
                bgp_neighbors[ip] = {
                    'asn': live.get('asn', 0),
                    'description': '(auto-detected)',
                    'active': True,
                    'state': live.get('state', 'up'),
                    'learned_v4': live.get('prefixes_v4', []),
                    'learned_v6': live.get('prefixes_v6', []),
                    'advertised_v4': [],
                    'advertised_v6': [],
                    'af_types': ['ipv4 unicast', 'ipv6 unicast'],
                }

    total_v4 = sum(len(n.get('prefixes_v4', [])) for n in neighbors.values())
    total_v6 = sum(len(n.get('prefixes_v6', [])) for n in neighbors.values())

    return jsonify({
        'success': True,
        'running': bgp_running,
        'local_as': bgp_local_config['local_as'],
        'router_id': bgp_local_config['router_id'],
        'neighbors': neighbors,
        'routes_v4': total_v4,
        'routes_v6': total_v6,
    })

# ─── Neighbor CRUD ───

@app.route('/api/bgp/neighbors', methods=['GET'])
def bgp_list_neighbors():
    return jsonify({'success': True, 'neighbors': bgp_neighbors})

@app.route('/api/bgp/neighbors', methods=['POST'])
def bgp_add_neighbor():
    global bgp_neighbors
    data = request.json
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'success': False, 'error': 'Peer IP required'}), 400
    if ip in bgp_neighbors:
        return jsonify({'success': False, 'error': f'Neighbor {ip} already exists'}), 400

    asn = int(data.get('asn', 65001))
    description = data.get('description', '')
    af_types = data.get('af_types', ['ipv4 unicast', 'ipv6 unicast'])
    active = data.get('active', True)

    bgp_neighbors[ip] = {
        'asn': asn,
        'description': description,
        'active': active,
        'state': 'configured',
        'learned_v4': [],
        'learned_v6': [],
        'advertised_v4': [],
        'advertised_v6': [],
        'af_types': af_types,
    }

    return jsonify({'success': True, 'message': f'Neighbor {ip} added', 'neighbor': bgp_neighbors[ip]})

@app.route('/api/bgp/neighbors/<path:ip>', methods=['DELETE'])
def bgp_delete_neighbor(ip):
    global bgp_neighbors
    ip = ip.replace('_', ':')  # allow URL-safe encoding
    if ip not in bgp_neighbors:
        return jsonify({'success': False, 'error': 'Neighbor not found'}), 404

    del bgp_neighbors[ip]
    return jsonify({'success': True, 'message': f'Neighbor {ip} removed'})

@app.route('/api/bgp/neighbors/<path:ip>/start', methods=['POST'])
def bgp_start_neighbor(ip):
    ip = ip.replace('_', ':')
    if ip not in bgp_neighbors:
        return jsonify({'success': False, 'error': 'Neighbor not found'}), 404

    bgp_neighbors[ip]['active'] = True
    bgp_neighbors[ip]['state'] = 'starting'

    # Restart ExaBGP with updated config
    ok, msg = _start_exabgp()
    if ok:
        bgp_neighbors[ip]['state'] = 'connecting'
        return jsonify({'success': True, 'message': f'Neighbor {ip} started'})
    else:
        bgp_neighbors[ip]['state'] = 'error'
        return jsonify({'success': False, 'error': msg}), 500

@app.route('/api/bgp/neighbors/<path:ip>/stop', methods=['POST'])
def bgp_stop_neighbor(ip):
    ip = ip.replace('_', ':')
    if ip not in bgp_neighbors:
        return jsonify({'success': False, 'error': 'Neighbor not found'}), 404

    bgp_neighbors[ip]['active'] = False
    bgp_neighbors[ip]['state'] = 'stopped'

    # Check if any active neighbors remain
    active_neighbors = [k for k, v in bgp_neighbors.items() if v.get('active', True)]
    if active_neighbors:
        _start_exabgp()  # restart without this neighbor
    else:
        _stop_exabgp()

    return jsonify({'success': True, 'message': f'Neighbor {ip} stopped'})

# ─── Per-Neighbor Routes ───

@app.route('/api/bgp/neighbors/<path:ip>/routes')
def bgp_neighbor_routes(ip):
    ip = ip.replace('_', ':')
    live = _parse_exabgp_log()
    nbr = bgp_neighbors.get(ip)
    live_info = live.get(ip, {})

    learned_v4 = live_info.get('prefixes_v4', nbr.get('learned_v4', []) if nbr else [])
    learned_v6 = live_info.get('prefixes_v6', nbr.get('learned_v6', []) if nbr else [])
    advertised_v4 = nbr.get('advertised_v4', []) if nbr else []
    advertised_v6 = nbr.get('advertised_v6', []) if nbr else []

    return jsonify({
        'success': True,
        'neighbor': ip,
        'learned': {'ipv4': learned_v4, 'ipv6': learned_v6},
        'advertised': {'ipv4': advertised_v4, 'ipv6': advertised_v6},
    })

@app.route('/api/bgp/neighbors/<path:ip>/advertise', methods=['POST'])
def bgp_advertise_route(ip):
    ip = ip.replace('_', ':')
    data = request.json
    prefix = data.get('prefix', '').strip()
    next_hop = data.get('next_hop', bgp_local_config['router_id'])

    if not prefix:
        return jsonify({'success': False, 'error': 'Prefix required'}), 400

    af = 'ipv6' if ':' in prefix else 'ipv4'
    if af == 'ipv6' and not (':' in str(next_hop)):
        next_hop = _get_local_ipv6()

    # Use text command format for exabgp-cli
    cmd = f"neighbor {ip} announce route {prefix} next-hop {next_hop}\n"

    try:
        result = subprocess.run(
            [EXABGP_CLI, '--pipename', '/home/cunshen/.local/run/exabgp'],
            input=cmd, text=True, timeout=5, capture_output=True
        )
        # Track advertised route in memory
        if ip in bgp_neighbors:
            key = f'advertised_{"v6" if af == "ipv6" else "v4"}'
            if prefix not in bgp_neighbors[ip].setdefault(key, []):
                bgp_neighbors[ip][key].append(prefix)

        return jsonify({'success': True, 'message': f'Advertised {prefix} to {ip}',
                        'output': result.stdout[:200] + result.stderr[:200]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bgp/neighbors/<path:ip>/withdraw', methods=['POST'])
def bgp_withdraw_route(ip):
    ip = ip.replace('_', ':')
    data = request.json
    prefix = data.get('prefix', '').strip()

    if not prefix:
        return jsonify({'success': False, 'error': 'Prefix required'}), 400

    cmd = f"neighbor {ip} withdraw route {prefix}\n"

    try:
        result = subprocess.run(
            [EXABGP_CLI, '--pipename', '/home/cunshen/.local/run/exabgp'],
            input=cmd, text=True, timeout=5, capture_output=True
        )

        # Remove from tracked advertised routes
        if ip in bgp_neighbors:
            af = 'ipv6' if ':' in prefix else 'ipv4'
            key = f'advertised_v{6 if af == "ipv6" else 4}'
            if prefix in bgp_neighbors[ip].get(key, []):
                bgp_neighbors[ip][key].remove(prefix)

        return jsonify({'success': True, 'message': f'Withdrawn {prefix} from {ip}',
                        'output': result.stdout[:200] + result.stderr[:200]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ─── Global Routes (for Traffic tab) ───

@app.route('/api/bgp/routes')
def bgp_all_routes():
    """Return all BGP-learned routes (IPv4+IPv6) for traffic stream selection."""
    routes = []
    live = _parse_exabgp_log()

    for ip, info in live.items():
        for r in info.get('prefixes_v4', []):
            prefix = r if isinstance(r, str) else r.get('prefix', '')
            routes.append({
                'prefix': prefix,
                'next_hop': r.get('next_hop', '') if isinstance(r, dict) else '',
                'af': 'ipv4', 'peer': ip
            })
        for r in info.get('prefixes_v6', []):
            prefix = r if isinstance(r, str) else r.get('prefix', '')
            routes.append({
                'prefix': prefix,
                'next_hop': r.get('next_hop', '') if isinstance(r, dict) else '',
                'af': 'ipv6', 'peer': ip
            })

    return jsonify({'success': True, 'routes': routes})

# ═══════════════════ TRex Host Management ═══════════════════

@app.route('/api/hosts')
def api_hosts():
    hosts_info = {}
    for name, h in trex_hosts.items():
        hosts_info[name] = {'ip': h['ip'], 'name': h['name'], 'connected': h['connected']}
    return jsonify({'success': True, 'hosts': hosts_info})

@app.route('/api/hosts', methods=['POST'])
def api_add_host():
    data = request.json
    name = data.get('name', f'host_{len(trex_hosts)}')
    ip = data.get('ip')
    if not ip:
        return jsonify({'success': False, 'error': 'IP required'}), 400
    trex_hosts[name] = {'ip': ip, 'name': data.get('display_name', name), 'client': None, 'connected': False}
    return jsonify({'success': True, 'host': {'name': name, 'ip': ip}})

@app.route('/api/hosts/<name>', methods=['DELETE'])
def api_delete_host(name):
    if name == 'local':
        return jsonify({'success': False, 'error': 'Cannot delete local host'}), 400
    h = trex_hosts.pop(name, None)
    return jsonify({'success': True})

# ═══════════════════ TRex Port Info ═══════════════════

@app.route('/api/ports')
def api_ports():
    host = request.args.get('host', 'local')
    try:
        c = get_trex_client(host)
        if not c:
            return jsonify({'success': False, 'error': f'Host {host} not connected'}), 500
        ports = []
        for p in [0, 1]:
            info = c.get_port_info(p)
            d = info[0] if isinstance(info, list) else info
            ports.append({
                'port': p, 'link': d.get('link', 'UNKNOWN'),
                'speed': d.get('speed', 0),
                'src_ip': d.get('src_ipv4', ''), 'dest': d.get('dest', ''),
                'src_mac': d.get('src_mac', ''), 'status': d.get('status', 'UNKNOWN'),
                'pci': d.get('pci_addr', '')
            })
        return jsonify({'success': True, 'ports': ports, 'host': host})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ═══════════════════ Enhanced Stats ═══════════════════

@app.route('/api/stats')
def api_stats():
    host = request.args.get('host', 'local')
    try:
        c = get_trex_client(host)
        if not c:
            return jsonify({'success': False, 'error': 'Not connected'}), 500
        stats = c.get_stats(ports=[0, 1])
        result = []
        for p in [0, 1]:
            s = stats[p]
            tx = s.get('opackets', 0)
            rx = s.get('ipackets', 0)
            loss_pct = round((tx - rx) / tx * 100, 2) if tx > 0 else 0.0
            result.append({
                'port': p,
                'tx_packets': tx, 'rx_packets': rx,
                'tx_bytes': s.get('obytes', 0), 'rx_bytes': s.get('ibytes', 0),
                'tx_pps': round(s.get('tx_pps', 0), 1), 'rx_pps': round(s.get('rx_pps', 0), 1),
                'tx_bps': round(s.get('tx_bps', 0), 1), 'rx_bps': round(s.get('rx_bps', 0), 1),
                'tx_errors': s.get('oerrors', 0), 'rx_errors': s.get('ierrors', 0),
                'loss_pct': loss_pct
            })

        latency_data = {}
        try:
            pg = c.get_pgid_stats()
            lat = pg.get('latency', {})
            for pg_id, data in lat.items():
                if pg_id == 'global': continue
                latency_data[pg_id] = {
                    'avg_us': round(data.get('latency', {}).get('average', 0), 1),
                    'max_us': data.get('latency', {}).get('total_max', 0),
                    'min_us': data.get('latency', {}).get('total_min', 0),
                    'jitter_us': data.get('latency', {}).get('jitter', 0),
                    'err_dropped': data.get('err_cntrs', {}).get('dropped', 0),
                    'err_ooo': data.get('err_cntrs', {}).get('out_of_order', 0),
                    'err_dup': data.get('err_cntrs', {}).get('dup', 0),
                }
        except: pass

        return jsonify({'success': True, 'stats': result, 'latency': latency_data})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ═══════════════════ Stream Management ═══════════════════

@app.route('/api/streams', methods=['GET'])
def api_list_streams():
    return jsonify({'success': True, 'streams': current_streams})

@app.route('/api/streams', methods=['POST'])
def api_create_stream():
    try:
        data = request.json
        host = data.get('host', 'local')
        port = int(data.get('port', 0))
        name = data.get('name', f'stream_{len(current_streams)}')

        src_ip = data.get('src_ip', '10.0.0.0' if port == 0 else '10.0.0.2')
        dst_ip = data.get('dst_ip', '10.0.0.1' if port == 0 else '10.0.0.3')
        ipv6 = ':' in dst_ip

        dst_mac_mode = data.get('dst_mac_mode', 'manual')
        dst_mac = data.get('dst_mac', 'e8:e4:9d:00:30:58')
        if dst_mac_mode == 'arp':
            resolved = arp_resolve(dst_ip)
            if resolved:
                dst_mac = resolved
        elif dst_mac_mode == 'gateway':
            gw_mac = get_gateway_mac()
            if gw_mac:
                dst_mac = gw_mac

        protocol = data.get('protocol', 'udp')
        src_port = int(data.get('src_port', 1234))
        dst_port = int(data.get('dst_port', 5678))

        pps = int(data.get('pps', 1000))
        bw_mbps = data.get('bw_mbps', 0)
        pkt_size = int(data.get('pkt_size', 64))
        if bw_mbps > 0:
            pps = bandwidth_to_pps(bw_mbps, pkt_size)
        actual_bw = pps_to_bandwidth(pps, pkt_size)

        dscp = int(data.get('dscp', 0))
        vlan_id = data.get('vlan_id', None)
        payload = data.get('payload', 'TRex_WebGUI_v4')

        enable_latency = data.get('enable_latency', True)
        pg_id = int(data.get('pg_id', 7))

        # Build packet
        if ipv6:
            pkt = Ether(dst=dst_mac) / IPv6(src=src_ip, dst=dst_ip, tc=dscp >> 2)
        else:
            pkt = Ether(dst=dst_mac) / IP(src=src_ip, dst=dst_ip, tos=dscp << 2)

        if vlan_id is not None and int(vlan_id) > 0:
            pkt = pkt / Dot1Q(vlan=int(vlan_id))

        if protocol == 'udp':
            pkt = pkt / UDP(sport=src_port, dport=dst_port)
        else:
            pkt = pkt / TCP(sport=src_port, dport=dst_port)

        pkt = pkt / Raw(payload.encode()[:pkt_size])

        c = get_trex_client(host)
        if not c:
            return jsonify({'success': False, 'error': f'Host {host} not connected'}), 500

        c.reset(ports=[port])
        c.remove_all_streams(ports=[port])

        stream_kwargs = {
            'name': name,
            'packet': STLPktBuilder(pkt=pkt),
            'mode': STLTXCont(pps=pps),
        }
        if enable_latency:
            stream_kwargs['flow_stats'] = STLFlowLatencyStats(pg_id=pg_id)

        stream = STLStream(**stream_kwargs)
        c.add_streams(stream, ports=[port])

        current_streams[name] = {
            'name': name, 'host': host, 'port': port,
            'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_mac': dst_mac,
            'protocol': protocol, 'pps': pps, 'pkt_size': pkt_size, 'bw_mbps': actual_bw,
            'src_port': src_port, 'dst_port': dst_port,
            'dscp': dscp, 'vlan_id': vlan_id,
            'pg_id': pg_id, 'latency_enabled': enable_latency,
            'ipv6': ipv6
        }
        return jsonify({'success': True, 'stream': current_streams[name]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/streams/<name>', methods=['DELETE'])
def api_delete_stream(name):
    try:
        s = current_streams.pop(name, None)
        if s:
            c = get_trex_client(s.get('host', 'local'))
            if c:
                c.remove_all_streams(ports=[s['port']])
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/start', methods=['POST'])
def api_start():
    try:
        data = request.json or {}
        ports = data.get('ports', [0, 1])
        duration = data.get('duration', -1)
        host = data.get('host', 'local')
        c = get_trex_client(host)
        if not c:
            return jsonify({'success': False, 'error': 'Host not connected'}), 500
        c.clear_stats()
        c.start(ports=ports, duration=duration if duration > 0 else -1)
        return jsonify({'success': True, 'message': 'Traffic started'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/stop', methods=['POST'])
def api_stop():
    try:
        host = (request.json or {}).get('host', 'local')
        c = get_trex_client(host)
        if c: c.stop()
        return jsonify({'success': True, 'message': 'Traffic stopped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/reset', methods=['POST'])
def api_reset():
    try:
        host = (request.json or {}).get('host', 'local')
        c = get_trex_client(host)
        if c:
            c.reset(ports=[0, 1])
        global current_streams
        current_streams = {}
        return jsonify({'success': True, 'message': 'Reset'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/trex_status')
def api_trex_status():
    host = request.args.get('host', 'local')
    try:
        c = get_trex_client(host)
        return jsonify({'success': True, 'running': c is not None, 'host': host})
    except:
        return jsonify({'success': True, 'running': False, 'host': host})

# ─── Init state ───
@app.route('/api/init')
def api_init():
    """Initialize complete state in one call."""
    result = {
        'bgp_running': _check_bgp_running(),
        'bgp_local_config': bgp_local_config,
        'bgp_neighbors': {},
        'trex_ok': False,
    }
    live = _parse_exabgp_log()
    for ip, nbr in bgp_neighbors.items():
        live_info = live.get(ip, {})
        result['bgp_neighbors'][ip] = {
            'asn': nbr['asn'],
            'description': nbr.get('description', ''),
            'active': nbr.get('active', True),
            'state': live_info.get('state', nbr.get('state', 'configured')),
            'prefixes_v4': live_info.get('prefixes_v4', []),
            'prefixes_v6': live_info.get('prefixes_v6', []),
            'advertised_v4': nbr.get('advertised_v4', []),
            'advertised_v6': nbr.get('advertised_v6', []),
            'af_types': nbr.get('af_types', []),
        }
    try:
        c = STLClient(server='127.0.0.1')
        c.connect()
        result['trex_ok'] = True
        c.disconnect()
    except:
        pass
    return jsonify({'success': True, **result})

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False, threaded=True)
