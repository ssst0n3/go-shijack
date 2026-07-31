#!/bin/bash
set +e
LOG=/tmp/h.log
: > "$LOG"
pkill -f 'go-shijack.*dns' 2>/dev/null
sleep 0.3
./go-shijack -t wlan0 -i 8.8.8.8 -p 53 --protocol dns --dns-domain example.com --dns-ip 1.2.3.4 -k >> "$LOG" 2>&1 &
HPID=$!
sleep 0.8
echo "=== dig ===" >> "$LOG"
dig @8.8.8.8 example.com +tries=1 +time=2 +short >> "$LOG" 2>&1
sleep 0.6
kill $HPID 2>/dev/null
echo "=== DONE ===" >> "$LOG"
