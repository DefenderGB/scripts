#!/bin/bash

echo "=============================================="
echo "Initiating Nmap Scan for open ports"
echo "Created by Gustavo Bobbio-Hertog (DefenderGB)"
echo "=============================================="

#Checking script syntax
if [[ $# -eq 0 ]] ; then
	echo "Wrong syntax!"
	echo "Usage example: sudo ./nmap_scan.sh 10.10.10.1"
	exit 1
else
	echo "Target: $1"
fi

#Get todays date, will use in filename
DATE=`date +%m-%d`
filename=$1_$DATE

#Port scan all ports, exports a nmap and port.txt file
echo ""
echo "[+] Running 0-65535 port scan..."
nmap -p 0-65535 --min-rate=1000 -T4 $1 -o scan-allports_$filename| grep ^[0-9] | cut -d "/" -f 1 | tr "\n" "," | sed s/,$// > ports.txt

#Presenting open ports
echo ""
echo "[+] Following ports are open:"
ports="$(cat ports.txt)"

if [[ "$ports" -eq 0 ]] ; then
	echo "No ports found. Try to run script using sudo OR add -Pn to nmap scans on this script."
	echo "Usage example: sudo ./nmap_scan.sh $1"
	exit 1
else
	echo "$(cat ports.txt)"
fi

#Default Script and Version Scan against open ports
echo ""
echo "[+] Running Default Scripts and Version scan on open ports:"
echo ""
nmap -T4 -sV -sC -p $ports $1 -o scan-default-script_$filename

#Vuln Scan against open ports
echo ""
echo "[+] Running Vuln Scripts on open ports:"
echo ""
nmap -T4 -sV --script vuln -p $ports $1 -o scan-vuln-script_$filename

#Recommendation
echo ""
echo "==========="
echo "Suggestions"
echo "==========="

if [[ "$ports" == *"80"* ]] ; then
	echo ""
	echo "===Port 80==="
	echo "[Suggest] Force Browse using gobuster:"
        echo "sudo gobuster dir -u http://$1/ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -o gobuster.out -x html,php,t"
        echo "[Suggest] SQLi: (Capture request (burp) that may be vulnerable to SQLi and use)" 
        echo "sqlmap -r login.req --batch"
        echo "[Suggest] Nikto VulnScan:"
        echo "nikto -h http://$1/"
fi

if [[ "$ports" == *"139"* ]] ; then
	echo ""
	echo "===Port 139==="
	echo "[Suggest] Use smbclient:"
	echo "smbclient -N -L //$1//"
fi

#Clean up
rm ports.txt
exit 0
