#!/usr/bin/env python3
"""TRex + BGP Web GUI — Traffic Gen, Route Control, Latency/Loss Stats"""

import sys, os, json, time, threading, subprocess, signal
sys.path.insert(0, '/opt/trex/automation/trex_control_plane/interactive')

from flask import Flask, jsonify, request, send_from_directory
from trex.stl.api import STLClient, STLStream, STLTXCont, STLPktBuilder, STLFlowLatencyStats
from scapy.all import Ether, IP, UDP, TCP, Raw
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__, static_folder='static', template_folder='templates')

TRex_HOST = '127.0.0.1'
_client = None
_client_lock = threading.Lock()
current_streams = {}
bgp_process = None
bgp_state = {'running': False, 'neighbors': {}, 'routes': [], 'local_as': 65000, 'router_id': '192.168.100.174'}

# ─── TRex Client ───
def get_client():
    global _client
    with _client_lock:
        if _client is None or not _client.connected:
            try:
                _client = STLClient(server=TRex_HOST)
                _client.connect()
                _client.acquire(ports=[0, 1], force=True)
            except:
                _client = None
        return _client

# ─── BGP Management ───
@app.route('/api/bgp/status')
def bgp_status():
    global bgp_state, bgp_process
    if bgp_process and bgp_process.poll() is None:
        bgp_state['running'] = True
    else:
        bgp_state['running'] = False
    # Load latest state from handler
    state_file = '/tmp/exabgp_state.json'
    if os.path.exists(state_file):
        try:
            with open(state_file) as f:
                s = json.load(f)
                bgp_state['neighbors'] = s.get('neighbors', {})
                bgp_state['routes'] = s.get('routes', [])
        except:
            pass
    return jsonify({'success': True, 'bgp': bgp_state})

@app.route('/api/bgp/config', methods=['POST'])
def bgp_config():
    data = request.json
    bgp_state['local_as'] = int(data.get('local_as', 65000))
    bgp_state['router_id'] = data.get('router_id', '192.168.100.174')
    return jsonify({'success': True, 'message': 'Config updated'})

@app.route('/api/bgp/start', methods=['POST'])
def bgp_start():
    global bgp_process, bgp_state
    if bgp_process and bgp_process.poll() is None:
        return jsonify({'success': True, 'message': 'BGP already running'})

    # Write exabgp config
    config = f'''neighbor 192.168.100.167 {{
    router-id {bgp_state['router_id']};
    local-as {bgp_state['local_as']};
    local-address 192.168.100.174;
    peer-as 65001;
    hold-time 30;
    api services {{ receive-routes; }}
}}
'''
    with open('/tmp/exabgp_running.conf', 'w') as f:
        f.write(config)

    try:
        bgp_process = subprocess.Popen(
            ['/home/cunshen/.local/bin/exabgp', '/tmp/exabgp_running.conf'],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid
        )
        time.sleep(2)
        if bgp_process.poll() is None:
            bgp_state['running'] = True
            return jsonify({'success': True, 'message': 'BGP started'})
        else:
            return jsonify({'success': False, 'error': 'BGP failed to start'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/bgp/stop', methods=['POST'])
def bgp_stop():
    global bgp_process, bgp_state
    if bgp_process:
        try:
            os.killpg(os.getpgid(bgp_process.pid), signal.SIGTERM)
        except:
            bgp_process.terminate()
        bgp_process = None
    bgp_state['running'] = False
    return jsonify({'success': True, 'message': 'BGP stopped'})

@app.route('/api/bgp/advertise', methods=['POST'])
def bgp_advertise():
    global bgp_process
    data = request.json
    prefix = data.get('prefix', '10.99.0.0/24')
    next_hop = data.get('next_hop', '192.168.100.174')

    cmd = json.dumps({
        'neighbor': {'ip': '192.168.100.167', 'send': {
            'update': {'announce': {'ipv4 unicast': {prefix: {'next-hop': next_hop}}}}
        }}
    })
    try:
        subprocess.run(
            fecho {cmd}
