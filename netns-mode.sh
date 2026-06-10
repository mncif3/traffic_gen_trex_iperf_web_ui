#!/usr/bin/env bash
# ============================================================================
# netns-mode.sh — UB-174 data-port mode controller for trex-web
#
# UB-174 runs TRex OR iPerf3, never both at once. Both subsystems use the SAME
# two physical 10G ports on the kernel i40e driver (NO vfio-pci, NO DPDK rebind).
# Switching modes just moves the two NICs between the iPerf3 namespaces and the
# single TRex namespace.
#
#   Port 0  enp8s0np0  (08:00.0)  -> switch 171 Eth513
#   Port 3  enp11s0np1 (0b:00.0)  -> switch 172 Eth513
#
# IPERF mode:  enp8s0np0 -> iperf_ns2 (10.0.0.0/31 side), enp11s0np1 -> iperf_ns (10.0.0.2/31 side)
# TREX  mode:  both NICs -> trex_ns, driven by TRex via af_packet (--vdev=net_af_packet)
#
# Usage:  sudo ./netns-mode.sh {iperf|trex|status|teardown}
# ============================================================================
set -euo pipefail

# ---- Edit these to match the box ----
P0_DEV="enp8s0np0"      # -> 171
P3_DEV="enp11s0np1"     # -> 172

# IPERF mode addressing (per-link /31; switch side is .1 / .3)
NS_171="iperf_ns2"; NS_171_IP="10.0.0.2/31"; NS_171_GW="10.0.0.3"
NS_172="iperf_ns";  NS_172_IP="10.20.0.0/31"; NS_172_GW="10.20.0.1"

# TREX mode: both ports live in one namespace so a single TRex process sees both
TREX_NS="trex_ns"
TREX_P0_IP="10.0.0.2/31"
TREX_P3_IP="10.20.0.0/31"

log(){ echo "[netns-mode] $*"; }

dev_to_root() {  # move a dev back to the root ns if it is in some other ns
  local dev="$1"
  for ns in "$NS_171" "$NS_172" "$TREX_NS"; do
    if ip netns list 2>/dev/null | grep -qw "$ns" && \
       ip netns exec "$ns" ip link show "$dev" &>/dev/null; then
      ip netns exec "$ns" ip link set "$dev" netns 1 || true
    fi
  done
}

teardown() {
  log "tearing down all data-port namespaces"
  pkill -9 iperf3 2>/dev/null || true
  # stop any TRex running in the namespace
  if ip netns list 2>/dev/null | grep -qw "$TREX_NS"; then
    ip netns exec "$TREX_NS" pkill -9 -f t-rex 2>/dev/null || true
  fi
  dev_to_root "$P0_DEV"; dev_to_root "$P3_DEV"
  for ns in "$NS_171" "$NS_172" "$TREX_NS"; do
    ip netns del "$ns" 2>/dev/null || true
  done
}

setup_iperf() {
  teardown
  log "IPERF mode: $P0_DEV->$NS_171 ($NS_171_IP), $P3_DEV->$NS_172 ($NS_172_IP)"
  ip netns add "$NS_171"; ip netns add "$NS_172"
  ip link set "$P0_DEV" netns "$NS_171"
  ip link set "$P3_DEV" netns "$NS_172"
  ip netns exec "$NS_171" ip addr add "$NS_171_IP" dev "$P0_DEV"
  ip netns exec "$NS_171" ip link set "$P0_DEV" up
  ip netns exec "$NS_171" ip link set lo up
  ip netns exec "$NS_172" ip addr add "$NS_172_IP" dev "$P3_DEV"
  ip netns exec "$NS_172" ip link set "$P3_DEV" up
  ip netns exec "$NS_172" ip link set lo up
  log "IPERF mode ready. iPerf3 / QoS tabs are now usable."
  ip netns exec "$NS_171" ip route add default via $NS_171_GW 2>/dev/null
  ip netns exec "$NS_172" ip route add default via $NS_172_GW 2>/dev/null
}

setup_trex() {
  teardown
  log "TREX mode: $P0_DEV + $P3_DEV -> $TREX_NS (af_packet)"
  ip netns add "$TREX_NS"
  ip link set "$P0_DEV" netns "$TREX_NS"
  ip link set "$P3_DEV" netns "$TREX_NS"
  ip netns exec "$TREX_NS" ip addr add "$TREX_P0_IP" dev "$P0_DEV"
  ip netns exec "$TREX_NS" ip addr add "$TREX_P3_IP" dev "$P3_DEV"
  ip netns exec "$TREX_NS" ip link set "$P0_DEV" up
  ip netns exec "$TREX_NS" ip link set "$P3_DEV" up
  ip netns exec "$TREX_NS" ip link set lo up
  log "TREX mode ready. Launch TRex inside the namespace, e.g.:"
  log "  ip netns exec $TREX_NS /opt/trex/t-rex-64 -i --cfg /etc/trex_cfg_afpacket.yaml"
}

status() {
  for ns in "$NS_171" "$NS_172" "$TREX_NS"; do
    if ip netns list 2>/dev/null | grep -qw "$ns"; then
      echo "== $ns =="
      ip netns exec "$ns" ip -4 -o addr show 2>/dev/null | grep 'inet ' || echo "  (no ipv4)"
    fi
  done
}

case "${1:-}" in
  iperf)    setup_iperf ;;
  trex)     setup_trex ;;
  status)   status ;;
  teardown) teardown ;;
  *) echo "usage: $0 {iperf|trex|status|teardown}"; exit 1 ;;
esac
