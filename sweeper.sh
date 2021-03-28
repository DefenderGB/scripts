#!/bin/bash

#Logo
echo " _____                                   "
echo "/  ___|                                  "
echo "\ \`--.__      _____  ___ _ __   ___ _ __ "
echo " \`--. \ \ /\ / / _ \/ _ \ '_ \ / _ \ '__|"
echo "/\__/ /\ V  V /  __/  __/ |_) |  __/ |   "
echo "\____/  \_/\_/ \___|\___| .__/ \___|_|   "
echo "                        | |              "
echo "                        |_|              "
echo "Created by Gustavo Bobbio-Hertog (DefenderGB)"
echo ""

#Checking script syntax
if [[ $# -eq 0 ]] ; then
	echo "[-] Wrong syntax!"
	echo "Usage example: sudo ./sweeper.sh 10.0.0.0/24"
	exit 1
else
	echo "[+] Target Network: $1"
fi

#Nmap Scan with output
nmap -PEPM -sP -n $1 -oG foundtargets 2>/dev/null

#Set variable
ips="$(cat foundtargets)"

#Print Results
echo "[+] Found Targets: (Comma seperated)"
echo $ips | tr "()" "\n" | grep 'Up Host' | cut -d ":" -f 3 | tr -d ' ' | tr "\\n" "," | sed 's/.$//' | sed -e '$a\'
echo "[+] Found Targets: (Columns)"
echo $ips | tr "()" "\n" | grep 'Up Host' | cut -d ":" -f 3 | tr -d ' ' | column
echo "[+] Found Targets: (List)"
echo $ips | tr "()" "\n" | grep 'Up Host' | cut -d ":" -f 3 | tr -d ' '
targetstring="$(echo '[+] Total Found Targets: ')"
totalstring="$(echo [+] Total Found Targets:  $ips | tr '()' '\n' | tail -2 | head -1 | cut -d ' ' -f 1)"
echo $targetstring $totalstring