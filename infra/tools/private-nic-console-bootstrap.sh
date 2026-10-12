# private-nic-console-bootstrap.sh :  first private-segment address for a node that
# has no reachable IP yet (so Ansible/SSH cannot reach it). Paste into a ROOT shell
# on the node's serial console (HPE iLO: `vsp`; exit with `Esc (`).
#
# It writes exactly the keyfile the Ansible private_net role writes, so a later
# role run adopts it instead of creating a competing profile.
#
# Safety: the private port is identified, never guessed. A duplicate-address probe
# (source 0.0.0.0, claims nothing) for the Lenovo's 10.88.0.2 is sent on every
# cabled Ethernet port; only a port whose reply comes from the Lenovo's PRIVATE
# MAC (eno2 02:00:00:00:00:05) is on the private switch. Any reply is not enough:
# the Lenovo's campus eno1 (…:ca) also answers ARP for 10.88.0.2 (Linux
# arp_ignore=0), so the campus 192.0.2.x L2 would otherwise match too
# (observed on .205, 2026-09-24).
# Nothing is written unless EXACTLY ONE port matches and the target address is free.
# No secrets are involved. Contains no default gateway by design.
#
# Set A to this node's planned address (docs/history/PRIVATE-LAB-NETWORK.md): g005 = 10.88.0.3.

A=10.88.0.3; M=""; for p in /sys/class/net/*; do i=${p##*/}; [ "$(cat $p/type)" = 1 ] && [ -e $p/device ] && [ "$(cat $p/carrier 2>/dev/null)" = 1 ] || continue; arping -D -I $i -c 2 -w 3 10.88.0.2 | grep -qi '02:00:00:00:00:05' && M="$M $i"; done; echo "ports that see the Lenovo private NIC:${M:- NONE}"

set -- $M; if [ $# -eq 1 ] && arping -D -q -I $1 -c 2 -w 3 $A; then I=$1; F=/etc/NetworkManager/system-connections/private-$I.nmconnection; printf '# Managed by Ansible private_net. Do not edit by hand.\n[connection]\nid=private-%s\ntype=ethernet\ninterface-name=%s\nautoconnect=true\nzone=public\n\n[ipv4]\nmethod=manual\naddress1=%s/24\nnever-default=true\n\n[ipv6]\nmethod=disabled\n\n[proxy]\n' $I $I $A > $F; chmod 600 $F; restorecon $F; nmcli con reload; nmcli con up private-$I; ip -br addr show $I; ip route; else echo "STOP: need exactly one matching port and a free $A (ports:${M:- none}) - nothing written"; fi
