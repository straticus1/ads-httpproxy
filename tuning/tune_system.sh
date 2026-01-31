#!/bin/bash
# High Performance Tuning Script for ads-httpproxy
# Target: 1M+ Concurrent Connections

echo "Applying Kernel Tuning for High Concurrency..."

# 1. File Descriptors
ulimit -n 1048576

# 2. Ephemeral Ports & TCP Reuse
sysctl -w net.ipv4.ip_local_port_range="1024 65535"
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.core.somaxconn=65535
sysctl -w net.core.netdev_max_backlog=5000
sysctl -w net.ipv4.tcp_max_syn_backlog=8096

# 3. Connection Tracking (if using firewall)
sysctl -w net.netfilter.nf_conntrack_max=1048576

echo "Kernel settings applied."

echo "Applying Go Runtime Tuning..."
export GOGC=off
export GOMEMLIMIT=12GiB

echo "Ready to launch ads-httpproxy in C10M mode."
