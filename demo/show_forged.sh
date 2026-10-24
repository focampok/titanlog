#!/usr/bin/env bash
# Titan.Log demo opener: show the forged JSONL before loading it in the app.
# Usage: bash demo/show_forged.sh   (press Enter to advance each step)
set -u
F="${1:-demo/forged_incident.jsonl}"
C='\033[1;36m'; R='\033[1;31m'; Y='\033[1;33m'; G='\033[1;32m'; N='\033[0m'
step(){ echo; echo -e "${C}▶ $1${N}"; read -r -p "  [Enter]" _; }

clear
echo -e "${C}TITAN.LOG — forged incident demo${N}"
echo -e "File: $F  ($(wc -l < "$F") lines)  ${Y}REAL = OTRF Security-Datasets · SIMULATED = injected by test harness${N}"

step "1/4  Open it in a normal JSON viewer..."
if command -v jless >/dev/null; then jless "$F" </dev/null 2>&1 | head -n 3 || true
else python3 -c "import json,sys;[json.loads(l) for l in open(sys.argv[1])]" "$F" 2>&1 | tail -n 1; fi
echo -e "${R}  ✗ A standard viewer crashes on the malformed line.${N}"

step "2/4  What is inside (line by line)"
python3 - "$F" <<'PY'
import json,sys
for i,l in enumerate(open(sys.argv[1]),1):
    try: d=json.loads(l)
    except Exception: print(f"\033[1;31m{i:>3}  MALFORMED  (broken JSON)\033[0m"); continue
    ts=str(d.get('@timestamp') or d.get('TimeCreated') or '')
    host=d.get('Hostname') or d.get('host'); eid=d.get('EventID')
    if d.get('_titan_label')=='SIMULATED_INJECTION':
        print(f"\033[1;33m{i:>3}  ⚠ SIMULATED INJECTION  EventID {eid}  {host}\033[0m")
    elif not host and not eid:
        print(f"\033[0;37m{i:>3}  AMBIGUOUS  (no host / user / EventID)\033[0m")
    elif ts[5:7] > '12':
        print(f"\033[1;31m{i:>3}  MALFORMED  (impossible timestamp {ts[:19]})\033[0m")
    else:
        print(f"{i:>3}  real     EventID {str(eid):<5} {host}")
PY

step "3/4  The attacker's note hidden in the real logs"
python3 - "$F" <<'PY'
import json,sys,re
for i,l in enumerate(open(sys.argv[1]),1):
    try: d=json.loads(l)
    except Exception: continue
    if d.get('_titan_label')=='SIMULATED_INJECTION':
        for k in ('CommandLine','Message'):
            v=str(d.get(k) or '')
            m=re.search(r'Authorized-Security-Test[^"\n]*',v)
            if m: print(f"\033[1;33m  line {i} [{k}]:\033[0m  …{m.group(0)}")
PY
echo -e "${Y}  A naive AI agent reads this and may close a real attack as benign.${N}"

step "4/4  Now load it in Titan.Log → sidebar: 'Load demo: forged incident'"
echo -e "${G}  Expected: 2 quarantined · 1 insufficient evidence · 2 ⚠ SIMULATED flagged · incident still detected · close=false${N}"
