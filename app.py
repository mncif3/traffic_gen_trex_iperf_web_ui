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
bgp_running = False
bgp_local_config = {'local_as': 65000, 'router_id': '192.168.100.174'}
bgp_neighbors = {}  # {ip: {asn, description, active, state, learned_v4, learned_v6, advertised_v4, advertised_v6, af_types}}
BGP_STATE_FILE = '/opt/trex-web/bgp_state.json'

def _save_bgp_state():
    try:
        with open(BGP_STATE_FILE, 'w') as f:
            json.dump(bgp_neighbors, f, indent=2)
    except Exception:
        pass

def _load_bgp_state():
    global bgp_neighbors
    try:
        with open(BGP_STATE_FILE) as f:
            bgp_neighbors = json.load(f)
    except Exception:
        pass


# BIRD runs inside data-plane namespaces (source IP = namespace IP)
BIRD_NS = {
    'iperf_ns2': {'local_ip': '10.0.0.2', 'local_ipv6': '2001:db8:513::2', 'switch_ip': '10.0.0.3',
                  'conf': '/tmp/bird/ns2.conf', 'sock': '/tmp/bird/ns2.ctl'},
    'iperf_ns':  {'local_ip': '10.20.0.0', 'local_ipv6': '2001:db8:514::2', 'switch_ip': '10.20.0.1',
                  'conf': '/tmp/bird/ns.conf',  'sock': '/tmp/bird/ns.ctl'},
}
BIRD_BIN = '/usr/sbin/bird'
BIRDC    = '/usr/sbin/birdc'

def _ns_for_neighbor(ip):
    if '.' in ip:
        if ip.startswith('10.0.0.'): return 'iperf_ns2'
        if ip.startswith('10.20.0.'): return 'iperf_ns'
    elif ':' in ip:
        if '2001:db8:513:' in ip: return 'iperf_ns2'
        if '2001:db8:514:' in ip: return 'iperf_ns'
    return None

_load_bgp_state()

# TRex hosts
trex_hosts = {
    'local': {'ip': '127.0.0.1', 'name': 'UB-174 (local)', 'client': None, 'connected': False}
}
current_streams = {}

# ═══════════════════ iPerf3 State ═══════════════════
iperf_streams = {}  # {id: {protocol, bind_ip, bind_dev, target_ip, port, ...}}
iperf_next_id = 1

IPERF_NAMESPACES = ['iperf_ns2', 'iperf_ns']  # iperf_ns2 -> sw171 Eth513, iperf_ns -> sw172 Eth513

def _get_interfaces():
    """List IPs configured inside the iPerf3/TRex namespaces (Src IP dropdown options).

    Bug 1 fix: the data-plane IPs live inside the network namespaces, not in the
    container's default namespace, so we must enumerate each namespace explicitly.
    Returns e.g. [{"name":"iperf_ns2","ipv4":["10.0.0.2"],"ipv6":[]}, ...].
    """
    import json as _json
    interfaces = []
    for ns in IPERF_NAMESPACES:
        try:
            result = subprocess.run(
                ['sudo', 'ip', 'netns', 'exec', ns, 'ip', '-j', 'addr'],
                capture_output=True, text=True, timeout=5)
            if result.returncode != 0 or not result.stdout.strip():
                continue
            ipv4_list, ipv6_list = [], []
            for iface in _json.loads(result.stdout):
                for a in iface.get('addr_info', []):
                    addr = a.get('local', '')
                    if a.get('family') == 'inet':
                        # skip loopback and the management subnet
                        if addr.startswith('127.') or addr.startswith('192.168.100.'):
                            continue
                        ipv4_list.append(addr)
                    elif a.get('family') == 'inet6' and a.get('scope') == 'global':
                        ipv6_list.append(addr)
            if ipv4_list or ipv6_list:
                interfaces.append({'name': ns, 'ipv4': ipv4_list, 'ipv6': ipv6_list})
        except Exception:
            continue
    return interfaces

def _parse_iperf_json(output):
    """Parse iperf3 JSON output into structured result."""
    try:
        import json as _json
        data = _json.loads(output)
    except:
        return {'error': 'Failed to parse iperf output', 'raw': output[-500:]}

    if data.get('error'):
        return {'error': data['error']}

    connected = data.get('start', {}).get('connected', [])
    conn0 = connected[0] if connected else {}
    result = {
        'protocol': data.get('start', {}).get('test_start', {}).get('protocol', '?'),
        'local_host': conn0.get('local_host', ''),
        'remote_host': conn0.get('remote_host', ''),
        'port': conn0.get('port', 0),
        'duration': 0, 'total_bytes': 0, 'bitrate_bps': 0,
        'retransmits': 0, 'jitter_ms': 0, 'lost_packets': 0, 'lost_percent': 0,
        'intervals': []
    }

    for interval in data.get('intervals', []):
        sums = interval.get('sum', {})
        result['duration'] = sums.get('end', 0)
        result['total_bytes'] += sums.get('bytes', 0)
        result['bitrate_bps'] = sums.get('bits_per_second', 0)
        result['retransmits'] += sums.get('retransmits', 0)
        if 'jitter_ms' in sums:
            result['jitter_ms'] = max(result['jitter_ms'], sums.get('jitter_ms', 0))
        result['lost_packets'] += sums.get('lost_packets', 0)
        result['lost_percent'] = max(result['lost_percent'], sums.get('lost_percent', 0))
        result['intervals'].append({
            'start': sums.get('start', 0),
            'end': sums.get('end', 0),
            'bytes': sums.get('bytes', 0),
            'bitrate_bps': sums.get('bits_per_second', 0),
            'retransmits': sums.get('retransmits', 0),
            'jitter_ms': sums.get('jitter_ms', 0),
            'lost_packets': sums.get('lost_packets', 0),
            'lost_percent': sums.get('lost_percent', 0),
        })

    # End summary
    end = data.get('end', {})
    if 'sum_sent' in end:
        s = end['sum_sent']
        result['total_bytes'] = s.get('bytes', result['total_bytes'])
        result['bitrate_bps'] = s.get('bits_per_second', result['bitrate_bps'])
        result['retransmits'] = s.get('retransmits', result['retransmits'])
    if 'sum' in end:
        s = end['sum']
        result['lost_packets'] = s.get('lost_packets', result['lost_packets'])
        result['lost_percent'] = s.get('lost_percent', result['lost_percent'])
        result['jitter_ms'] = s.get('jitter_ms', result['jitter_ms'])

    result['bitrate_mbps'] = round(result['bitrate_bps'] / 1e6, 2)
    result['total_MB'] = round(result['total_bytes'] / 1e6, 2)
    return result

def _build_iperf_cmd(stream, role='client'):
    """Build iperf3 command line for a stream."""
    cmd = ['iperf3']
    if role == 'server':
        # Bug 2 fix: do NOT bind the server to a specific address. Binding with
        # `-B <ip>` makes iperf3 -s exit 1 when that IP is not assignable in the
        # namespace. Listen on all addresses in the namespace, matching the proven
        # /api/qos/run path (iperf3 -s -D -1 --port N). The client still targets the
        # server IP explicitly via -c.
        cmd += ['-s', '-1']
        if stream.get('port'):
            cmd += ['-p', str(stream['port'])]
        return cmd

    # ── Client mode ──
    cmd += ['-c', stream['target_ip']]
    if stream.get('port'):
        cmd += ['-p', str(stream['port'])]
    if stream.get('bind_ip'):
        cmd += ['-B', stream['bind_ip']]
    if stream.get('protocol') == 'udp':
        cmd += ['-u']
    if stream.get('bandwidth'):
        cmd += ['-b', stream['bandwidth']]
    if stream.get('packet_size'):
        cmd += ['-l', str(stream['packet_size'])]
    if stream.get('duration'):
        cmd += ['-t', str(stream['duration'])]
    if stream.get('parallel', 1) > 1:
        cmd += ['-P', str(stream['parallel'])]
    if stream.get('interval'):
        cmd += ['-i', str(stream['interval'])]
    if stream.get('dscp'):
        cmd += ['--dscp', str(stream['dscp'])]
    if stream.get('window'):
        cmd += ['-w', stream['window']]
    if stream.get('mss'):
        cmd += ['-M', str(stream['mss'])]
    if stream.get('omit'):
        cmd += ['-O', str(stream['omit'])]
    if stream.get('connect_timeout'):
        cmd += ['--connect-timeout', str(stream['connect_timeout'])]
    if stream.get('zerocopy'):
        cmd += ['-Z']
    if stream.get('reverse'):
        cmd += ['-R']
    if stream.get('bidirectional'):
        cmd += ['--bidir']
    cmd += ['-J']
    return cmd

def _run_iperf_server(stream_id):
    """Run iperf3 server in background for a stream (in netns for physical path)."""
    stream = iperf_streams.get(stream_id)
    if not stream:
        return
    cmd = _build_iperf_cmd(stream, 'server')
    # Wrap with netns so traffic goes through physical switch
    cmd = ['sudo', 'ip', 'netns', 'exec', 'iperf_ns'] + cmd
    try:
        # Use DEVNULL to avoid pipe buffering issues
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        stream['server_process'] = proc
        stream['server_running'] = True
        # Verify it actually started
        time.sleep(0.3)
        if proc.poll() is not None:
            stream['server_running'] = False
            stream['last_result'] = {'error': f'Server exited immediately (code {proc.returncode})'}
        else:
            print(f'[iperf] Server started: PID {proc.pid} on port {stream.get("port")}', flush=True)
    except Exception as e:
        stream['server_running'] = False
        stream['last_result'] = {'error': f'Server start failed: {e}'}
        print(f'[iperf] Server start error: {e}', flush=True)

def _run_iperf_client(stream_id):
    """Run iperf3 client and parse results."""
    stream = iperf_streams.get(stream_id)
    if not stream:
        return
    cmd = _build_iperf_cmd(stream, 'client')
    cmd = ['sudo', 'ip', 'netns', 'exec', 'iperf_ns2'] + cmd
    print(f'[iperf] Client command: {" ".join(cmd)}', flush=True)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=stream.get('duration', 10) + 10)
        stream['client_running'] = False
        print(f'[iperf] Client exit code: {proc.returncode}', flush=True)
        if proc.stdout:
            result = _parse_iperf_json(proc.stdout)
            stream['last_result'] = result
            stream['last_result_raw'] = proc.stdout[-2000:]
        elif proc.stderr:
            stream['last_result'] = {'error': proc.stderr[:500]}
            stream['last_result_raw'] = proc.stderr[-1000:]
        else:
            stream['last_result'] = {'error': 'No output from iperf3'}
    except subprocess.TimeoutExpired:
        stream['client_running'] = False
        stream['last_result'] = {'error': 'iperf client timed out'}
    except Exception as e:
        stream['client_running'] = False
        stream['last_result'] = {'error': f'Client exception: {e}'}
        print(f'[iperf] Client exception: {e}', flush=True)

# ─── iPerf3 API Routes ───
@app.route('/api/iperf/interfaces')
def iperf_interfaces():
    return jsonify({'success': True, 'interfaces': _get_interfaces()})

@app.route('/api/iperf/streams', methods=['GET'])
def iperf_list():
    result = {}
    for sid, s in iperf_streams.items():
        result[sid] = {
            'id': sid,
            'protocol': s.get('protocol', 'tcp'),
            'bind_ip': s.get('bind_ip', ''),
            'bind_dev': s.get('bind_dev', ''),
            'target_ip': s.get('target_ip', ''),
            'port': s.get('port', 5201),
            'duration': s.get('duration', 10),
            'bandwidth': s.get('bandwidth', ''),
            'packet_size': s.get('packet_size', ''),
            'dscp': s.get('dscp', ''),
            'parallel': s.get('parallel', 1),
            'interval': s.get('interval', 1),
            'bidirectional': s.get('bidirectional', False),
            'reverse': s.get('reverse', False),
            'window': s.get('window', ''),
            'mss': s.get('mss', ''),
            'omit': s.get('omit', 0),
            'connect_timeout': s.get('connect_timeout', 0),
            'zerocopy': s.get('zerocopy', False),
            'server_running': s.get('server_running', False),
            'client_running': s.get('client_running', False),
            'last_result': s.get('last_result', {}),
        }
    return jsonify({'success': True, 'streams': result})

@app.route('/api/iperf/streams', methods=['POST'])
def iperf_create():
    global iperf_next_id
    data = request.json or {}
    sid = f'iperf_{iperf_next_id}'
    iperf_next_id += 1

    iperf_streams[sid] = {
        'id': sid,
        'protocol': data.get('protocol', 'tcp'),
        'bind_ip': data.get('bind_ip', ''),
        'bind_dev': data.get('bind_dev', ''),
        'target_ip': data.get('target_ip', ''),
        'port': int(data.get('port', 5201)),
        'duration': int(data.get('duration', 10)),
        'bandwidth': data.get('bandwidth', ''),
        'packet_size': data.get('packet_size', ''),
        'dscp': data.get('dscp', ''),
        'parallel': int(data.get('parallel', 1)),
        'interval': int(data.get('interval', 1)),
        'bidirectional': bool(data.get('bidirectional', False)),
        'reverse': bool(data.get('reverse', False)),
        'window': data.get('window', ''),
        'mss': data.get('mss', ''),
        'omit': int(data.get('omit', 0)),
        'connect_timeout': int(data.get('connect_timeout', 0)),
        'zerocopy': bool(data.get('zerocopy', False)),
        'server_running': False,
        'client_running': False,
        'server_process': None,
        'last_result': {},
    }
    return jsonify({'success': True, 'id': sid, 'stream': iperf_streams[sid]})

@app.route('/api/iperf/streams/<sid>', methods=['DELETE'])
def iperf_delete(sid):
    s = iperf_streams.pop(sid, None)
    if not s:
        return jsonify({'success': False, 'error': 'Not found'}), 404
    # Kill any running processes
    for key in ('server_process',):
        proc = s.get(key)
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except:
                proc.kill()
    return jsonify({'success': True})

@app.route('/api/iperf/streams/<sid>', methods=['PUT'])
def iperf_update(sid):
    stream = iperf_streams.get(sid)
    if not stream:
        return jsonify({'success': False, 'error': 'Stream not found'}), 404
    data = request.json or {}
    updatable = ['protocol', 'bind_ip', 'bind_dev', 'target_ip', 'port', 'duration',
                 'bandwidth', 'packet_size', 'dscp', 'parallel', 'interval',
                 'bidirectional', 'reverse', 'window', 'mss', 'omit',
                 'connect_timeout', 'zerocopy']
    for key in updatable:
        if key in data:
            stream[key] = data[key]
    # Return sanitized stream (no Popen objects)
    safe = {k: v for k, v in stream.items() if k not in ('server_process', 'last_result_raw')}
    return jsonify({'success': True, 'stream': safe})

@app.route('/api/iperf/streams/batch/start', methods=['POST'])
def iperf_batch_start():
    ids = (request.json or {}).get('ids', [])
    if not ids:
        return jsonify({'success': False, 'error': 'No stream IDs provided'}), 400
    started = []
    failed = []
    for sid in ids:
        s = iperf_streams.get(sid)
        if not s:
            failed.append({'id': sid, 'error': 'Not found'})
            continue
        # Kill previous server
        old_proc = s.get('server_process')
        if old_proc and old_proc.poll() is None:
            try: old_proc.terminate(); old_proc.wait(timeout=2)
            except: old_proc.kill()
        # Kill lingering
        port = s.get('port', 5201)
        try: subprocess.run(['pkill', '-f', f'iperf3.*-s.*-p {port}'], timeout=2)
        except: pass
        time.sleep(0.2)
        # Start server
        s['last_result'] = {}
        cmd = _build_iperf_cmd(s, 'server')
        try:
            proc = subprocess.Popen(["sudo", "ip", "netns", "exec", "iperf_ns"] + cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.5)
            if proc.poll() is not None:
                s['last_result'] = {'error': f'Server exited code {proc.returncode}'}
                failed.append({'id': sid, 'error': 'Server failed'})
                continue
            s['server_process'] = proc
            s['server_running'] = True
        except Exception as e:
            s['last_result'] = {'error': str(e)}
            failed.append({'id': sid, 'error': str(e)})
            continue
        # Start client thread
        s['client_running'] = True
        threading.Thread(target=_run_iperf_client, args=(sid,), daemon=True).start()
        started.append(sid)
    return jsonify({'success': True, 'started': started, 'failed': failed})

@app.route('/api/iperf/streams/<sid>/start', methods=['POST'])
def iperf_start(sid):
    stream = iperf_streams.get(sid)
    if not stream:
        return jsonify({'success': False, 'error': 'Stream not found'}), 404

    print(f'[iperf] start() called for {sid}', flush=True)

    # Kill any previous server for this stream
    old_proc = stream.get('server_process')
    if old_proc and old_proc.poll() is None:
        try:
            old_proc.terminate()
            old_proc.wait(timeout=3)
        except:
            old_proc.kill()

    # Kill any lingering iperf3 servers on the same port
    port = stream.get('port', 5201)
    try:
        subprocess.run(['pkill', '-f', f'iperf3.*-s.*-p {port}'], timeout=3)
    except:
        pass
    time.sleep(0.3)

    # Start server SYNCHRONOUSLY first to verify it works
    stream['last_result'] = {}
    cmd = _build_iperf_cmd(stream, 'server')
    print(f'[iperf] Starting server: {" ".join(cmd)}', flush=True)
    try:
        proc = subprocess.Popen(["sudo", "ip", "netns", "exec", "iperf_ns"] + cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        if proc.poll() is not None:
            stream['server_running'] = False
            stream['last_result'] = {'error': f'Server exited code {proc.returncode}'}
            print(f'[iperf] Server exited immediately (code {proc.returncode})', flush=True)
            return jsonify({'success': False, 'error': 'Server failed to start'})
        stream['server_process'] = proc
        stream['server_running'] = True
        print(f'[iperf] Server PID {proc.pid} running on port {port}', flush=True)
    except Exception as e:
        stream['server_running'] = False
        stream['last_result'] = {'error': f'Server exception: {e}'}
        print(f'[iperf] Server exception: {e}', flush=True)
        return jsonify({'success': False, 'error': str(e)})

    # Start client in background thread
    stream['client_running'] = True
    client_thread = threading.Thread(target=_run_iperf_client, args=(sid,), daemon=True)
    client_thread.start()

    print(f'[iperf] Client thread started for {sid}', flush=True)
    return jsonify({'success': True, 'message': f'iperf stream {sid} started'})

@app.route('/api/iperf/streams/<sid>/stop', methods=['POST'])
def iperf_stop(sid):
    stream = iperf_streams.get(sid)
    if not stream:
        return jsonify({'success': False, 'error': 'Stream not found'}), 404

    proc = stream.get('server_process')
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except:
            proc.kill()
    stream['server_process'] = None
    stream['server_running'] = False
    stream['client_running'] = False

    try:
        subprocess.run(['pkill', '-f', 'iperf3.*-s'], timeout=3)
    except:
        pass

    return jsonify({'success': True, 'message': f'iperf stream {sid} stopped'})

@app.route('/api/iperf/streams/<sid>/status')
def iperf_status(sid):
    stream = iperf_streams.get(sid)
    if not stream:
        return jsonify({'success': False, 'error': 'Stream not found'}), 404

    proc = stream.get('server_process')
    server_alive = proc and proc.poll() is None if proc else False

    return jsonify({
        'success': True,
        'server_running': server_alive,
        'client_running': stream.get('client_running', False),
        'result': stream.get('last_result', {}),
    })

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

# ═══════════════════ BGP: BIRD Control (namespace-aware) ═══════════════════
# BIRD 2.x runs INSIDE each data-plane namespace so source IP matches the
# physical port IP.  The HTTP API contract is unchanged so index.html is fine.

BIRD_BIN = '/usr/sbin/bird'
BIRDC    = '/usr/sbin/birdc'

def _birdc_ns(ns, *args):
    """Run birdc inside a namespace. Returns (ok, output)."""
    cfg = BIRD_NS.get(ns)
    if not cfg: return False, f'Unknown namespace: {ns}'
    try:
        r = subprocess.run(
            ['sudo', 'ip', 'netns', 'exec', ns, BIRDC, '-s', cfg['sock']] + list(args),
            capture_output=True, text=True, timeout=8)
        return r.returncode == 0, (r.stdout or '') + (r.stderr or '')
    except Exception as e:
        return False, str(e)

def _birdc(peer_ip, *args):
    """Run birdc in the namespace that owns this peer IP."""
    ns = _ns_for_neighbor(peer_ip)
    if not ns: return False, f'No namespace for {peer_ip}'
    return _birdc_ns(ns, *args)

def _proto_name(ip):
    return 'peer_' + re.sub(r'[^0-9a-zA-Z]', '_', ip)

def _bird_state_to_status(bird_info):
    s = (bird_info or '').lower()
    if 'establ' in s: return 'established'
    if any(k in s for k in ('active', 'connect', 'opensent', 'openconfirm')): return 'connecting'
    if 'idle' in s: return 'idle'
    return s.strip() or 'unknown'

def _get_local_ipv6():
    try:
        r = subprocess.run(['ip', '-6', 'addr', 'show', 'scope', 'global'],
                           capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            m = re.search(r'inet6\s+([0-9a-f:]+)/\d+', line)
            if m and not m.group(1).startswith('fe80'): return m.group(1)
    except Exception: pass
    return '::1'

# ── Config builder (per-namespace) ──

def _build_bird_configs():
    """Generate BIRD configs for all namespaces with active neighbors."""
    local_as = bgp_local_config['local_as']
    active_total = 0
    for ns, cfg in BIRD_NS.items():
        lines = [
            '# Auto-generated by trex-web.',
            'log syslog all;',
            f'router id {cfg["local_ip"]};',
            '', 'protocol device { }', '',
        ]
        ns_active = 0
        for ip, nbr in bgp_neighbors.items():
            if _ns_for_neighbor(ip) != ns or not nbr.get('active', True):
                continue
            ns_active += 1
            pname = _proto_name(ip)
            is_v6 = ':' in ip
            local_addr = cfg.get('local_ipv6', _get_local_ipv6()) if is_v6 else cfg['local_ip']

            adv4 = nbr.get('advertised_v4', [])
            adv6 = nbr.get('advertised_v6', [])
            if adv4:
                lines.append(f'protocol static static4_{pname} {{')
                lines.append('    ipv4;')
                for pfx in adv4: lines.append(f'    route {pfx} blackhole;')
                lines.append('}')
            if adv6:
                lines.append(f'protocol static static6_{pname} {{')
                lines.append('    ipv6;')
                for pfx in adv6: lines.append(f'    route {pfx} blackhole;')
                lines.append('}')

            af_list = nbr.get('af_types', ['ipv4 unicast', 'ipv6 unicast'])
            want4 = any('ipv4' in a for a in af_list)
            want6 = any('ipv6' in a for a in af_list)

            lines.append(f'protocol bgp {pname} {{')
            lines.append(f'    local {local_addr} as {local_as};')
            lines.append(f'    neighbor {ip} as {nbr["asn"]};')
            lines.append('    hold time 30;')
            if want4:
                exp4 = f'export where proto = "static4_{pname}";' if adv4 else 'export none;'
                lines.append('    ipv4 {')
                lines.append('        import all;')
                lines.append(f'        {exp4}')
                lines.append('        next hop self;')
                lines.append('    };')
            if want6:
                exp6 = f'export where proto = "static6_{pname}";' if adv6 else 'export none;'
                lines.append('    ipv6 {')
                lines.append('        import all;')
                lines.append(f'        {exp6}')
                lines.append('        next hop self;')
                lines.append('    };')
            lines.append('}')
        active_total += ns_active
        os.makedirs(os.path.dirname(cfg['conf']), exist_ok=True)
        with open(cfg['conf'], 'w') as f:
            f.write(chr(10).join(lines) + chr(10))
    return active_total

# ── Daemon lifecycle ──

def _bird_daemon_running():
    try:
        r = subprocess.run(['pgrep', '-x', 'bird'], capture_output=True, text=True, timeout=3)
        return bool(r.stdout.strip())
    except Exception: return False

def _start_bird():
    """Start BIRD in each namespace that has active neighbors."""
    global bgp_running
    active = _build_bird_configs()
    if active == 0:
        _stop_bird()
        return False, "No active neighbors"
    ok_all = True
    for ns, cfg in BIRD_NS.items():
        os.makedirs(os.path.dirname(cfg['sock']), exist_ok=True)
        # Check if BIRD already running in this namespace
        _, out = _birdc_ns(ns, 'show', 'status')
        running = 'BIRD' in (out or '')
        if running:
            ok, out2 = _birdc_ns(ns, 'configure')
            if not ok: ok_all = False
        else:
            try:
                r = subprocess.run(
                    ['sudo', 'ip', 'netns', 'exec', ns, BIRD_BIN,
                     '-c', cfg['conf'], '-s', cfg['sock']],
                    capture_output=True, text=True, timeout=8)
                time.sleep(1)
                if not _bird_daemon_running():
                    ok_all = False
            except Exception:
                ok_all = False
    bgp_running = ok_all
    return ok_all, "BGP started" if ok_all else "BIRD start failed"

def _stop_bird():
    global bgp_running
    for ns in BIRD_NS:
        _birdc_ns(ns, 'down')
    try: subprocess.run(['sudo', 'pkill', '-x', 'bird'], timeout=5)
    except: pass
    bgp_running = False

def _check_bgp_running():
    global bgp_running
    bgp_running = _bird_daemon_running()
    return bgp_running

# ── Live state parsing ──

def _bird_show_protocols_ns(ns):
    ok, out = _birdc_ns(ns, 'show', 'protocols')
    protos = {}
    if not ok: return protos
    for line in out.splitlines():
        toks = line.split()
        if len(toks) >= 2 and toks[1] == 'BGP':
            info = ' '.join(toks[5:]) if len(toks) > 5 else (toks[3] if len(toks) > 3 else '')
            protos[toks[0]] = info
    return protos

def _bird_routes_for_ns(ns, pname):
    v4, v6 = [], []
    ok, out = _birdc_ns(ns, 'show', 'route', 'protocol', pname, 'all')
    if not ok: return v4, v6
    cur = None
    for line in out.splitlines():
        m = re.match(r'^([0-9a-fA-F:.]+/\d+)\b', line)
        if m:
            cur = m.group(1)
            nh = ''
            mvia = re.search(r'via\s+(\S+)', line)
            if mvia: nh = mvia.group(1)
            (v6 if ':' in cur else v4).append({'prefix': cur, 'next_hop': nh})
        else:
            mvia = re.search(r'via\s+(\S+)', line)
            if mvia and cur:
                bucket = v6 if ':' in cur else v4
                if bucket and not bucket[-1]['next_hop']:
                    bucket[-1]['next_hop'] = mvia.group(1)
    return v4, v6

def _parse_bird_live():
    """Aggregate live BGP state from ALL namespace BIRD instances."""
    result = {}
    for ip, nbr in bgp_neighbors.items():
        ns = _ns_for_neighbor(ip)
        if not ns: continue
        pname = _proto_name(ip)
        protos = _bird_show_protocols_ns(ns)
        state = _bird_state_to_status(protos.get(pname))
        v4, v6 = ([], [])
        if state == 'established':
            v4, v6 = _bird_routes_for_ns(ns, pname)
        result[ip] = {
            'state': state if state != 'unknown' else nbr.get('state', 'configured'),
            'asn': nbr.get('asn', 0),
            'prefixes_v4': v4, 'prefixes_v6': v6,
        }
    return result

# ═══════════════════ BGP: API Endpoints ═══════════════════

@app.route('/api/bgp/status')
def bgp_status():
    """Overall BGP status with all neighbors."""
    _check_bgp_running()
    live_peers = _parse_bird_live()

    neighbors = {}
    for ip, nbr in bgp_neighbors.items():
        live = live_peers.get(ip, {})
        state = live.get('state', nbr.get('state', 'configured'))
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
        if live.get('prefixes_v4'):
            nbr['learned_v4'] = live['prefixes_v4']
        if live.get('prefixes_v6'):
            nbr['learned_v6'] = live['prefixes_v6']
        nbr['state'] = state

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
        'asn': asn, 'description': description,
        'active': active, 'state': 'configured',
        'learned_v4': [], 'learned_v6': [],
        'advertised_v4': [], 'advertised_v6': [],
        'af_types': af_types,
    }
    _save_bgp_state()
    return jsonify({'success': True, 'message': f'Neighbor {ip} added', 'neighbor': bgp_neighbors[ip]})

@app.route('/api/bgp/neighbors/<path:ip>', methods=['DELETE'])
def bgp_delete_neighbor(ip):
    global bgp_neighbors
    ip = ip.replace('_', ':')
    if ip not in bgp_neighbors:
        return jsonify({'success': False, 'error': 'Neighbor not found'}), 404
    del bgp_neighbors[ip]
    _save_bgp_state()
    if any(v.get('active', True) for v in bgp_neighbors.values()):
        _start_bird()
    else:
        _stop_bird()
    return jsonify({'success': True, 'message': f'Neighbor {ip} removed'})

@app.route('/api/bgp/neighbors/<path:ip>/start', methods=['POST'])
def bgp_start_neighbor(ip):
    ip = ip.replace('_', ':')
    if ip not in bgp_neighbors:
        return jsonify({'success': False, 'error': 'Neighbor not found'}), 404
    bgp_neighbors[ip]['active'] = True
    bgp_neighbors[ip]['state'] = 'starting'
    _save_bgp_state()
    ok, msg = _start_bird()
    if ok:
        bgp_neighbors[ip]['state'] = 'connecting'
        return jsonify({'success': True, 'message': f'Neighbor {ip} started'})
    bgp_neighbors[ip]['state'] = 'error'
    return jsonify({'success': False, 'error': msg}), 500

@app.route('/api/bgp/neighbors/<path:ip>/stop', methods=['POST'])
def bgp_stop_neighbor(ip):
    ip = ip.replace('_', ':')
    if ip not in bgp_neighbors:
        return jsonify({'success': False, 'error': 'Neighbor not found'}), 404
    bgp_neighbors[ip]['active'] = False
    bgp_neighbors[ip]['state'] = 'stopped'
    _save_bgp_state()
    active_neighbors = [k for k, v in bgp_neighbors.items() if v.get('active', True)]
    if active_neighbors:
        _start_bird()
    else:
        _stop_bird()
    return jsonify({'success': True, 'message': f'Neighbor {ip} stopped'})

@app.route('/api/bgp/neighbors/<path:ip>/routes')
def bgp_neighbor_routes(ip):
    ip = ip.replace('_', ':')
    live = _parse_bird_live()
    nbr = bgp_neighbors.get(ip)
    live_info = live.get(ip, {})
    learned_v4 = live_info.get('prefixes_v4', nbr.get('learned_v4', []) if nbr else [])
    learned_v6 = live_info.get('prefixes_v6', nbr.get('learned_v6', []) if nbr else [])
    advertised_v4 = nbr.get('advertised_v4', []) if nbr else []
    advertised_v6 = nbr.get('advertised_v6', []) if nbr else []
    return jsonify({
        'success': True, 'neighbor': ip,
        'learned': {'ipv4': learned_v4, 'ipv6': learned_v6},
        'advertised': {'ipv4': advertised_v4, 'ipv6': advertised_v6},
    })

@app.route('/api/bgp/neighbors/<path:ip>/advertise', methods=['POST'])
def bgp_advertise_route(ip):
    ip = ip.replace('_', ':')
    data = request.json or {}
    prefix = data.get('prefix', '').strip()
    if not prefix:
        return jsonify({'success': False, 'error': 'Prefix required'}), 400
    if ip not in bgp_neighbors:
        return jsonify({'success': False, 'error': 'Neighbor not found'}), 404
    key = 'advertised_v6' if ':' in prefix else 'advertised_v4'
    if prefix not in bgp_neighbors[ip].setdefault(key, []):
        bgp_neighbors[ip][key].append(prefix)
        _save_bgp_state()
    ok, msg = _start_bird()
    if not ok:
        if prefix in bgp_neighbors[ip].get(key, []):
            bgp_neighbors[ip][key].remove(prefix)
            _save_bgp_state()
        return jsonify({'success': False, 'error': msg}), 500
    return jsonify({'success': True, 'message': f'Advertised {prefix} to {ip}'})

@app.route('/api/bgp/neighbors/<path:ip>/withdraw', methods=['POST'])
def bgp_withdraw_route(ip):
    ip = ip.replace('_', ':')
    data = request.json or {}
    prefix = data.get('prefix', '').strip()
    if not prefix:
        return jsonify({'success': False, 'error': 'Prefix required'}), 400
    if ip not in bgp_neighbors:
        return jsonify({'success': False, 'error': 'Neighbor not found'}), 404
    key = 'advertised_v6' if ':' in prefix else 'advertised_v4'
    if prefix in bgp_neighbors[ip].get(key, []):
        bgp_neighbors[ip][key].remove(prefix)
        _save_bgp_state()
    ok, msg = _start_bird()
    if not ok:
        return jsonify({'success': False, 'error': msg}), 500
    return jsonify({'success': True, 'message': f'Withdrawn {prefix} from {ip}'})

@app.route('/api/bgp/routes')
def bgp_all_routes():
    routes = []
    live = _parse_bird_live()
    for ip, info in live.items():
        for r in info.get('prefixes_v4', []):
            prefix = r if isinstance(r, str) else r.get('prefix', '')
            routes.append({'prefix': prefix,
                           'next_hop': r.get('next_hop', '') if isinstance(r, dict) else '',
                           'af': 'ipv4', 'peer': ip})
        for r in info.get('prefixes_v6', []):
            prefix = r if isinstance(r, str) else r.get('prefix', '')
            routes.append({'prefix': prefix,
                           'next_hop': r.get('next_hop', '') if isinstance(r, dict) else '',
                           'af': 'ipv6', 'peer': ip})
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

def _get_ns_iface_status(ns, iface):
    try:
        r = subprocess.run(['sudo', 'ip', 'netns', 'exec', ns, 'ip', '-j', 'addr', 'show', iface],
                          capture_output=True, text=True, timeout=5)
        if r.returncode != 0: return None
        info = json.loads(r.stdout)
        if not info: return None
        addr_info = info[0]
        ips = [a['local'] for a in addr_info.get('addr_info',[]) if a.get('family')=='inet']
        ips6 = [a['local'] for a in addr_info.get('addr_info',[]) if a.get('family')=='inet6' and not a['local'].startswith('fe80')]
        mac = addr_info.get('address', '-')
        link = 'UP' if 'UP' in addr_info.get('flags',[]) else 'DOWN'
        return {'ip': ips[0] if ips else '-', 'ip6': ips6[0] if ips6 else '-', 'mac': mac, 'link': link}
    except: return None

@app.route('/api/ports')
def api_ports():
    host = request.args.get('host', 'local')
    try:
        c = get_trex_client(host)
        if not c:
            # TRex not running - show namespace interface status
            p0 = _get_ns_iface_status('iperf_ns2', 'enp8s0np0')
            p1 = _get_ns_iface_status('iperf_ns', 'enp11s0np1')
            ports = [
                {'port': 0, 'link': p0['link'] if p0 else 'DOWN', 'speed': 10,
                 'src_ip': p0['ip'] if p0 else '-', 'src_ip6': p0['ip6'] if p0 else '-',
                 'dest': '171 Eth513', 'src_mac': p0['mac'] if p0 else '-',
                 'status': 'iperf mode', 'pci': '08:00.0'},
                {'port': 1, 'link': p1['link'] if p1 else 'DOWN', 'speed': 10,
                 'src_ip': p1['ip'] if p1 else '-', 'src_ip6': p1['ip6'] if p1 else '-',
                 'dest': '172 Eth513', 'src_mac': p1['mac'] if p1 else '-',
                 'status': 'iperf mode', 'pci': '0b:00.0'}
            ]
            return jsonify({'success': True, 'ports': ports, 'host': host, 'trex': False})
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
        return jsonify({'success': True, 'ports': ports, 'host': host, 'trex': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ═══════════════════ Namespace Management ═══════════════════

NS_CONFIG_FILE = '/opt/trex-web/ns_config.json'

def _load_ns_config():
    try:
        with open(NS_CONFIG_FILE) as f:
            return json.load(f)
    except:
        return {}

def _save_ns_config(config):
    with open(NS_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def _get_ns_live_status(ns_name):
    """Get live namespace status: interfaces, IPs, routes."""
    try:
        interfaces = {}
        # IPv4 addresses
        r4 = subprocess.run(['sudo', 'ip', 'netns', 'exec', ns_name, 'ip', '-4', '-o', 'addr', 'show'],
                           capture_output=True, text=True, timeout=5)
        if r4.returncode != 0:
            return None
        for line in r4.stdout.strip().split('\n'):
            if not line: continue
            parts = line.split()
            iface = parts[1]; ip = parts[3]
            if iface not in interfaces: interfaces[iface] = {}
            interfaces[iface]['ipv4'] = ip

        # IPv6 addresses (skip link-local)
        r6 = subprocess.run(['sudo', 'ip', 'netns', 'exec', ns_name, 'ip', '-6', '-o', 'addr', 'show'],
                           capture_output=True, text=True, timeout=5)
        for line in r6.stdout.strip().split('\n'):
            if not line or 'scope link' in line: continue
            parts = line.split()
            iface = parts[1]; ip = parts[3]
            if iface in interfaces:
                interfaces[iface]['ipv6'] = ip

        # IPv4 routes (skip kernel proto, keep default + static)
        routes = []
        r_route = subprocess.run(['sudo', 'ip', 'netns', 'exec', ns_name, 'ip', '-4', 'route', 'show'],
                                capture_output=True, text=True, timeout=5)
        for line in r_route.stdout.strip().split('\n'):
            if not line or 'proto kernel' in line: continue
            routes.append({'af': 'ipv4', 'route': line.strip()})

        # IPv6 routes
        r6_route = subprocess.run(['sudo', 'ip', 'netns', 'exec', ns_name, 'ip', '-6', 'route', 'show'],
                                 capture_output=True, text=True, timeout=5)
        for line in r6_route.stdout.strip().split('\n'):
            if not line or 'proto kernel' in line or 'fe80::/64' in line: continue
            routes.append({'af': 'ipv6', 'route': line.strip()})

        return {'interfaces': interfaces, 'routes': routes}
    except:
        return None

@app.route('/api/namespaces', methods=['GET'])
def api_list_namespaces():
    config = _load_ns_config()
    try:
        r = subprocess.run(['ip', 'netns', 'list'], capture_output=True, text=True, timeout=5)
        ns_list = [line.split()[0] for line in r.stdout.strip().split('\n') if line]
    except:
        ns_list = []

    result = []
    for ns_name in ns_list:
        live = _get_ns_live_status(ns_name)
        cfg = config.get(ns_name, {})
        result.append({
            'name': ns_name,
            'description': cfg.get('description', ns_name),
            'interface': cfg.get('interface', ''),
            'ipv4': cfg.get('ipv4', ''),
            'ipv6': cfg.get('ipv6', ''),
            'gateway': cfg.get('gateway', ''),
            'gateway6': cfg.get('gateway6', ''),
            'static_routes': cfg.get('static_routes', []),
            'live': live
        })

    return jsonify({'success': True, 'namespaces': result})

@app.route('/api/namespaces', methods=['POST'])
def api_create_namespace():
    data = request.get_json()
    name = data.get('name', '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'Name required'}), 400

    config = _load_ns_config()
    config[name] = {
        'description': data.get('description', name),
        'interface': data.get('interface', ''),
        'ipv4': data.get('ipv4', ''),
        'ipv6': data.get('ipv6', ''),
        'gateway': data.get('gateway', ''),
        'gateway6': data.get('gateway6', ''),
        'static_routes': data.get('static_routes', [])
    }
    _save_ns_config(config)

    if data.get('apply'):
        try:
            r = subprocess.run(['ip', 'netns', 'list'], capture_output=True, text=True)
            if name not in r.stdout:
                subprocess.run(['sudo', 'ip', 'netns', 'add', name], check=True, timeout=10)

            iface = data.get('interface', '')
            if iface:
                # Move from root if present there
                subprocess.run(['sudo', 'ip', 'link', 'set', iface, 'netns', name], check=True, timeout=10)

            if data.get('ipv4'):
                subprocess.run(['sudo', 'ip', 'netns', 'exec', name, 'ip', 'addr', 'add',
                              data['ipv4'], 'dev', iface], check=True, timeout=10)
            if data.get('ipv6'):
                subprocess.run(['sudo', 'ip', 'netns', 'exec', name, 'ip', '-6', 'addr', 'add',
                              data['ipv6'], 'dev', iface], check=True, timeout=10)

            subprocess.run(['sudo', 'ip', 'netns', 'exec', name, 'ip', 'link', 'set', iface, 'up'],
                          check=True, timeout=10)
            subprocess.run(['sudo', 'ip', 'netns', 'exec', name, 'ip', 'link', 'set', 'lo', 'up'],
                          check=True, timeout=10)

            if data.get('gateway'):
                subprocess.run(['sudo', 'ip', 'netns', 'exec', name, 'ip', 'route', 'add',
                              'default', 'via', data['gateway']], check=False, timeout=10)

            for route in data.get('static_routes', []):
                prefix = route.get('prefix', '')
                via = route.get('next_hop', '')
                if prefix and via:
                    af = '-6' if ':' in prefix else ''
                    cmd = ['sudo', 'ip', 'netns', 'exec', name, 'ip', 'route', 'add', prefix, 'via', via]
                    if af:
                        cmd.insert(5, af)
                    subprocess.run(cmd, check=False, timeout=10)
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500

    return jsonify({'success': True, 'namespace': config[name]})

@app.route('/api/namespaces/<name>', methods=['PUT'])
def api_update_namespace(name):
    data = request.get_json()
    config = _load_ns_config()
    if name not in config:
        return jsonify({'success': False, 'error': 'Namespace not found'}), 404

    for field in ['description', 'interface', 'ipv4', 'ipv6', 'gateway', 'gateway6', 'static_routes']:
        if field in data:
            config[name][field] = data[field]
    _save_ns_config(config)
    return jsonify({'success': True, 'namespace': config[name]})

@app.route('/api/namespaces/<name>', methods=['DELETE'])
def api_delete_namespace(name):
    config = _load_ns_config()
    if name in config:
        del config[name]
        _save_ns_config(config)
    try:
        subprocess.run(['sudo', 'ip', 'netns', 'del', name], check=False, timeout=10)
    except:
        pass
    return jsonify({'success': True})

@app.route('/api/namespaces/ports', methods=['GET'])
def api_available_ports():
    """List available 10G physical ports (X710 family) for namespace assignment."""
    try:
        r = subprocess.run(['ip', '-br', 'link', 'show'], capture_output=True, text=True, timeout=5)
        all_ifaces = {}
        for line in r.stdout.strip().split('\n'):
            parts = line.split()
            if len(parts) >= 2:
                all_ifaces[parts[0]] = {'state': parts[1], 'mac': parts[2] if len(parts) > 2 else ''}

        x710_ports = ['enp8s0np0', 'enp9s0np3', 'enp10s0np2', 'enp11s0np1']
        in_ns = set()
        try:
            r_ns = subprocess.run(['ip', 'netns', 'list'], capture_output=True, text=True, timeout=5)
            for ns in [l.split()[0] for l in r_ns.stdout.strip().split('\n') if l]:
                r_links = subprocess.run(['sudo', 'ip', 'netns', 'exec', ns, 'ip', '-br', 'link', 'show'],
                                        capture_output=True, text=True, timeout=5)
                for line in r_links.stdout.strip().split('\n'):
                    iface = line.split()[0] if line else ''
                    if iface: in_ns.add(iface)
        except:
            pass

        ports = []
        for p in x710_ports:
            info = all_ifaces.get(p, {'state': 'UNKNOWN', 'mac': ''})
            ports.append({
                'name': p, 'state': info['state'], 'mac': info['mac'],
                'in_namespace': p in in_ns
            })
        return jsonify({'success': True, 'ports': ports})
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
            # TRex not running — save stream config for later use
            current_streams[name] = {
                'name': name, 'host': host, 'port': port,
                'src_ip': src_ip, 'dst_ip': dst_ip, 'dst_mac': dst_mac,
                'protocol': protocol, 'pps': pps, 'pkt_size': pkt_size, 'bw_mbps': actual_bw,
                'src_port': src_port, 'dst_port': dst_port,
                'dscp': dscp, 'vlan_id': vlan_id,
                'pg_id': pg_id, 'latency_enabled': enable_latency,
                'ipv6': ipv6, 'pending': True
            }
            return jsonify({'success': True, 'stream': current_streams[name],
                          'warning': 'TRex not running — stream saved, will apply when TRex starts'})

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
    live = _parse_bird_live()
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

# ═══════════════════ QoS Test API ═══════════════════

QOS_DSCP_MAP = {
    '8':  {'tc': '0', 'queue': 'Q0', 'pg': '0',  'label': 'CS0 (Best-Effort)', 'weight': '10'},
    '24': {'tc': '3', 'queue': 'Q3', 'pg': '3',  'label': 'RDMA/RoCEv2 (PFC)',  'weight': '90'},
    '32': {'tc': '4', 'queue': 'Q4', 'pg': '4',  'label': 'Lossless (PFC)',     'weight': '-'},
    '48': {'tc': '6', 'queue': 'Q6', 'pg': '0',  'label': 'CNP/STRICT',          'weight': '-'},
}

SERVER_IP4 = '10.20.0.0'
SERVER_IP6 = '2001:db8:20::2'

@app.route('/api/qos/mapping')
def api_qos_mapping():
    return jsonify({'success': True, 'mapping': QOS_DSCP_MAP})

@app.route('/api/qos/run', methods=['POST'])
def api_qos_run():
    try:
        data = request.json
        dscp = int(data.get('dscp', 24))
        ipv6 = data.get('ipv6', False)
        duration = int(data.get('duration', 5))

        if ipv6:
            cmd = f"sudo ip netns exec iperf_ns2 iperf3 -c {SERVER_IP6} -t {duration} -P 1 --dscp {dscp} -J"
        else:
            cmd = f"sudo ip netns exec iperf_ns2 iperf3 -c {SERVER_IP4} -t {duration} -P 1 --dscp {dscp} -J"

        # Start server first
        subprocess.run(f"sudo pkill -9 iperf3 2>/dev/null; sudo ip netns exec iperf_ns iperf3 -s -D -1 --port 5201", shell=True, timeout=5)
        time.sleep(0.5)

        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=duration+10)
        output = result.stdout.strip() or result.stderr.strip()

        # Parse iperf3 JSON output
        throughput = None
        retransmits = None
        try:
            j = json.loads(output)
            if 'end' in j and 'sum_received' in j['end']:
                sr = j['end']['sum_received']
                throughput = round(sr.get('bits_per_second', 0) / 1e9, 2)
                retransmits = j['end'].get('sum_sent', {}).get('retransmits', 'N/A')
            elif 'end' in j and 'sum_sent' in j['end']:
                ss = j['end']['sum_sent']
                throughput = round(ss.get('bits_per_second', 0) / 1e9, 2)
                retransmits = ss.get('retransmits', 'N/A')
        except:
            pass

        return jsonify({
            'success': True,
            'dscp': dscp,
            'ipv6': ipv6,
            'throughput_gbps': throughput,
            'retransmits': retransmits,
            'raw_output': output[:2000]
        })
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'iperf3 timeout'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/qos/switches')
def api_qos_switches():
    """Get queue counters from 171 and 172."""
    result = {}
    for sw_ip, iface in [('192.168.100.171', 'Ethernet513'), ('192.168.100.172', 'Ethernet513')]:
        try:
            cmd = f"sshpass -p 'YourPaSsWoRd' ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o ConnectTimeout=5 -o LogLevel=ERROR admin@{sw_ip}"
            r = subprocess.run(f"{cmd} 'show queue counters {iface} 2>&1 | grep UC'",
                              shell=True, capture_output=True, text=True, timeout=10)
            lines = r.stdout.strip().split('\n')
            counters = {}
            for line in lines:
                parts = line.split()
                if len(parts) >= 3:
                    qname = parts[1]  # UC0, UC1, ...
                    pkts = int(parts[2]) if parts[2].isdigit() else 0
                    counters[qname] = pkts
            result[sw_ip] = {'iface': iface, 'queues': counters, 'error': None}
        except Exception as e:
            result[sw_ip] = {'iface': iface, 'queues': {}, 'error': str(e)}
    return jsonify({'success': True, 'switches': result})

@app.route('/api/qos/clear_counters', methods=['POST'])
def api_qos_clear_counters():
    """Clear queue counters on both switches."""
    for sw_ip in ['192.168.100.171', '192.168.100.172']:
        try:
            cmd = f"sshpass -p 'YourPaSsWoRd' ssh -o StrictHostKeyChecking=no -o PreferredAuthentications=password -o ConnectTimeout=5 -o LogLevel=ERROR admin@{sw_ip}"
            subprocess.run(f"{cmd} 'sonic-clear queuecounters'", shell=True, capture_output=True, timeout=10)
        except:
            pass
    return jsonify({'success': True})

@app.route('/qos')
def qos_page():
    return send_from_directory('templates', 'qos_test.html')

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888, debug=False, threaded=True)
