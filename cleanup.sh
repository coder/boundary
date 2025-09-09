#!/bin/bash

# Emergency cleanup script for boundary network jail
# Run this if boundary crashes and leaves your networking in a bad state

echo "Cleaning up boundary network namespaces and iptables rules..."

# Remove all boundary network namespaces
for ns in $(ip netns list | grep boundary | awk '{print $1}'); do
    echo "Removing namespace: $ns"
    sudo ip netns delete "$ns" 2>/dev/null || true
done

# Remove boundary iptables rules
echo "Cleaning up iptables rules..."
sudo iptables -t nat -D POSTROUTING -s 192.168.100.0/24 -j MASQUERADE 2>/dev/null || true

# Remove any boundary interfaces
for iface in $(ip link show | grep veth_n_ | awk -F: '{print $2}' | awk '{print $1}'); do
    echo "Removing interface: $iface"
    sudo ip link delete "$iface" 2>/dev/null || true
done

# Clean up DNS config directories
echo "Cleaning up DNS configuration..."
sudo rm -rf /etc/netns/boundary_* 2>/dev/null || true

echo "Cleanup completed. Your networking should be restored."
echo "If you still have issues, try: sudo systemctl restart networking"
