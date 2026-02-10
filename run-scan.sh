#!/bin/bash
cd /root/clawd/headervet-dev

declare -A grade_hosts
grades=("A+" "A" "B" "C" "D" "E" "F")
for g in "${grades[@]}"; do grade_hosts[$g]=""; done

reachable=0
timeout_count=0
results_json="["

while IFS= read -r host; do
  json=$(node dist/index.js "https://$host" --json --timeout 5000 2>/dev/null)
  if [ $? -eq 0 ] && [ -n "$json" ]; then
    grade=$(echo "$json" | node -p "try{JSON.parse(require('fs').readFileSync('/dev/stdin','utf8')).grade}catch(e){}" 2>/dev/null)
    if [ -n "$grade" ] && [ "$grade" != "undefined" ] && [ "$grade" != "" ]; then
      echo "$host: $grade"
      reachable=$((reachable+1))
      if [ -n "${grade_hosts[$grade]}" ]; then
        grade_hosts[$grade]="${grade_hosts[$grade]},$host"
      else
        grade_hosts[$grade]="$host"
      fi
      if [ "$reachable" -gt 1 ]; then results_json="$results_json,"; fi
      results_json="$results_json{\"host\":\"$host\",\"grade\":\"$grade\"}"
    else
      echo "$host: TIMEOUT"
      timeout_count=$((timeout_count+1))
    fi
  else
    echo "$host: TIMEOUT"
    timeout_count=$((timeout_count+1))
  fi
done < /tmp/headervet-targets.txt

results_json="$results_json]"
echo "$results_json" > scan-results/rescan-results.json

echo "=== SUMMARY ==="
echo "REACHABLE=$reachable"
echo "TIMEOUT=$timeout_count"
for g in "${grades[@]}"; do
  hosts="${grade_hosts[$g]}"
  if [ -n "$hosts" ]; then
    count=$(echo "$hosts" | tr ',' '\n' | wc -l)
  else
    count=0
  fi
  echo "GRADE_${g}=$count"
  echo "HOSTS_${g}=$hosts"
done
