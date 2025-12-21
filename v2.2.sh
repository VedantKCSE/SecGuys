#!/bin/bash

# --- Styling ---
CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
MAGENTA='\033[0;35m'
RED='\033[0;31m'
NC='\033[0m'

TARGET="192.168.100.135"
LOG_DIR="scan_results"
mkdir -p "$LOG_DIR"

# --- Fixed Animated Spinner ---
spinner() {
    local delay=0.1
    local spinstr='|/-\'
    while [ -d /proc/$PID_NMAP ] || [ -d /proc/$PID_NUCLEI ]; do
        local temp=${spinstr#?}
        printf "\r ${CYAN}[%c] Parallel Engines Running (Nmap + Nuclei)...${NC}" "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
    done
    printf "\r${GREEN}[✔] Service Discovery & Vuln Scanning Complete!          ${NC}\n"
}

echo -e "${MAGENTA}======================================================${NC}"
echo -e "${CYAN}    PREDICTIVE INGESTOR v2.2 (Robust JSON Fix)${NC}"
echo -e "${MAGENTA}======================================================${NC}"

# 1. Start background tasks
(nmap -sV -T4 -p- -oX "$LOG_DIR/nmap.xml" "$TARGET" > /dev/null 2>&1) &
PID_NMAP=$!
(nuclei -u "http://$TARGET" -j -o "$LOG_DIR/nuclei.json" > /dev/null 2>&1) &
PID_NUCLEI=$!

spinner

# 2. Run SearchSploit
echo -e "${YELLOW}[>] Mapping Exploits...${NC}"
searchsploit --nmap "$LOG_DIR/nmap.xml" --json > "$LOG_DIR/exploits_raw.json" 2>/dev/null
echo -e "${GREEN}[✔] Exploit Mapping Complete!${NC}"

# 3. RUN ROBUST NORMALIZATION
echo -e "${YELLOW}[>] Normalizing data into final.json for AI...${NC}"

python3 <<EOF
import json
import xml.etree.ElementTree as ET
import os

final = {"target": "$TARGET", "findings": []}

# --- Step 1: Nmap XML ---
if os.path.exists("$LOG_DIR/nmap.xml"):
    try:
        tree = ET.parse("$LOG_DIR/nmap.xml")
        for port in tree.findall(".//port"):
            state = port.find("state")
            if state is not None and state.get("state") == "open":
                srv = port.find("service")
                final["findings"].append({
                    "port": port.get("portid"),
                    "service": srv.get("name") if srv is not None else "unknown",
                    "version": srv.get("version", "unknown") if srv is not None else "unknown",
                    "exploits": [],
                    "nuclei": []
                })
    except Exception as e: print(f"Nmap Error: {e}")

# --- Step 2: Nuclei JSONL ---
if os.path.exists("$LOG_DIR/nuclei.json"):
    with open("$LOG_DIR/nuclei.json", "r") as f:
        for line in f:
            try:
                data = json.loads(line)
                for fnd in final["findings"]:
                    if str(data.get("port")) == fnd["port"]:
                        fnd["nuclei"].append(data["info"].get("name", "Unknown"))
            except: continue

# --- Step 3: SearchSploit Robust Multi-Object Parsing ---
if os.path.exists("$LOG_DIR/exploits_raw.json"):
    with open("$LOG_DIR/exploits_raw.json", "r") as f:
        content = f.read()
        # Searchsploit often outputs: {obj1}{obj2} or {obj1}\n{obj2}
        # We use a raw decoder to pull multiple objects from one string
        decoder = json.JSONDecoder()
        pos = 0
        while pos < len(content):
            content = content.lstrip()
            if not content: break
            try:
                obj, index = decoder.raw_decode(content)
                # Process the object (Searchsploit puts results in RESULTS_EXPLOIT)
                for ex in obj.get("RESULTS_EXPLOIT", []):
                    for fnd in final["findings"]:
                        # Fuzzy match: check if service name is in exploit title
                        if fnd["service"].lower() in ex["Title"].lower() and fnd["service"] != "unknown":
                            if ex["Title"] not in fnd["exploits"]:
                                fnd["exploits"].append(ex["Title"])
                content = content[index:]
            except Exception:
                break

with open("final.json", "w") as f:
    json.dump(final, f, indent=2)
EOF

if [ -f "final.json" ]; then
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${GREEN}SUCCESS: 'final.json' created! (${NC}$(du -h final.json | cut -f1)${GREEN})${NC}"
    echo -e "${CYAN}Final JSON is now cleansed and compressed for AI analysis.${NC}"
else
    echo -e "${RED}FAILED to create final.json${NC}"
fi
