#!/bin/bash
# Read-only InfiniBand peer map of ONE node (D42 deferred work; run as root on a GPU node in an owned
# window, after infiniband-diags is installed): ssh root@<node> 'bash -s' < ib-peer-map.sh > <node>.txt
# For each InfiniBand port: its own identity from sysfs, and for a linked port its neighbour's
# identity by a directed-route NodeInfo query (smpquery -D ... 0,1), which needs no subnet manager
# and changes nothing. Every query's exit status and first error line are kept: a failed or empty
# query is printed as an error, never as a peer (tools/ib-peer-check.py refuses it).
# Output, one line each:
#   node <hostname>
#   tool smpquery <path|absent>
#   port <ca>/<port> guid=<port GUID> state=<n> phys=<n> pci=<address>
#   peer <ca>/<port> rc=<n> guid=<node GUID|-> port_guid=<port GUID|-> local_port=<n|-> type=<NodeType|-> error=<text|->
set -u
sysfs=${IB_SYSFS:-/sys/class/infiniband}
echo "node ${IB_NODE:-$(cat /proc/sys/kernel/hostname)}"   # IB_NODE, IB_SYSFS: tests only
smp=$(command -v smpquery || true)
echo "tool smpquery ${smp:-absent}"
field() { printf '%s\n' "$2" | sed -n "s/^$1:\.*//p" | head -n1 | tr -d ' '; }
for d in "$sysfs"/*; do
  [ -d "$d/ports" ] || continue
  ca=$(basename "$d")
  for p in "$d"/ports/*; do
    [ "$(cat "$p/link_layer" 2>/dev/null)" = InfiniBand ] || continue
    port=$(basename "$p")
    guid=$(cut -d: -f5-8 "$p/gids/0" 2>/dev/null)
    state=$(cut -d: -f1 "$p/state"); phys=$(cut -d: -f1 "$p/phys_state")
    echo "port $ca/$port guid=${guid:--} state=$state phys=$phys pci=$(basename "$(readlink -f "$d/device")")"
    [ "$phys" = 5 ] || continue                     # 5: LinkUp; a port without a link has no neighbour to ask
    if [ -z "$smp" ]; then
      echo "peer $ca/$port rc=127 guid=- port_guid=- local_port=- type=- error=smpquery_absent"; continue
    fi
    out=$(timeout 15 "$smp" -C "$ca" -P "$port" -D nodeinfo 0,1 2>&1); rc=$?
    g=$(field Guid "$out"); pg=$(field PortGuid "$out"); lp=$(field LocalPort "$out"); ty=$(field NodeType "$out" | tr -c 'A-Za-z\n' _)
    err=-; [ "$rc" = 0 ] || err=$(printf '%s' "$out" | head -n1 | tr -c 'A-Za-z0-9.:/=\n-' _)
    echo "peer $ca/$port rc=$rc guid=${g:--} port_guid=${pg:--} local_port=${lp:--} type=${ty:--} error=${err:--}"
  done
done
