#!/bin/bash
# scripts/netstat.sh
echo "---CONNECTION_COUNT---"
netstat -ntu | wc -l

echo "---TOP_IPS---"
netstat -ntu | awk '{print $5}' | cut -d: -f1 | grep -v '^$' | sort | uniq -c | sort -nr | head -20

echo "---SYN_RECV_IPS---"
netstat -n | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -20

echo "---STATE_COUNTS---"
netstat -nat | awk '{print $6}' | sort | uniq -c | sort -nr
