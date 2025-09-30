#!/bin/bash
# scripts/sysstats.sh
set -e
export PATH="/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin:$PATH"

cpu_usage=$(top -bn1 | awk '/Cpu\(s\)/{print 100-$8}')
cpu_load=$(uptime | awk -F'load average:' '{print $2}' | cut -d',' -f1 | tr -d ' ')
ram_usage=$(free | awk '/Mem:/ {printf("%.2f", $3/$2 * 100)}')
disk_usage=$(df -h / | awk 'NR==2 {gsub(/%/,"",$5); print $5}')
storage_free=$(df -h / | awk 'NR==2 {print $4}')
total_processes=$(ps aux | wc -l)
total_threads=$(ps -eLf | wc -l)
total_handles=$(command -v lsof >/dev/null 2>&1 && lsof | wc -l || echo 0)

cat <<EOF
{
  "cpu_usage": "$cpu_usage",
  "cpu_load": "$cpu_load",
  "ram_usage": "$ram_usage",
  "disk_usage": "$disk_usage",
  "storage_free": "$storage_free",
  "total_processes": "$total_processes",
  "total_threads": "$total_threads",
  "total_handles": "$total_handles"
}
EOF
