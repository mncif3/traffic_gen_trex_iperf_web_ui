#!/usr/bin/env python3
import sys, json, os
STATE_FILE = '/tmp/exabgp_state.json'
def read_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f: return json.load(f)
    return {'neighbors': {}, 'routes': []}
def write_state(s):
    with open(STATE_FILE, 'w') as f: json.dump(s, f)
state = read_state()
while True:
    try:
        line = sys.stdin.readline()
        if not line: break
        msg = json.loads(line.strip())
        t = msg.get('type', '')
        if t == 'state':
            state['neighbors'][msg['neighbor']['ip']] = msg['neighbor']['state']
            write_state(state)
        elif t == 'update':
            nlri = msg['neighbor']['message']['update'].get('announce', {}).get('ipv4 unicast', {})
            for prefix, data in nlri.items():
                route = {'prefix': prefix, 'next_hop': data.get('next-hop', ''), 'origin': 'bgp'}
                if route not in state['routes']: state['routes'].append(route)
            withdraw = msg['neighbor']['message']['update'].get('withdraw', {}).get('ipv4 unicast', {})
            for prefix in withdraw:
                state['routes'] = [r for r in state['routes'] if r['prefix'] != prefix]
            write_state(state)
    except: pass
