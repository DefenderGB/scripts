#!/bin/bash

echo "     __                       __                 "
echo "  /\ \ \_ __ ___   __ _ _ __ / _\ ___ __ _ _ __  "
echo " /  \/ / '_ \` _ \ / _\` | '_ \\\\ \ / __/ _\` | '_ \ "
echo "/ /\  /| | | | | | (_| | |_) |\ \ (_| (_| | | | |"
echo "\_\ \/ |_| |_| |_|\__,_| .__/\__/\___\__,_|_| |_|"
echo "                       |_|                       "
echo "    Created by Gustavo Bobbio-Hertog (DefenderGB)"
echo ""

#Checking script syntax
if [[ $# -eq 0 ]] ; then
	echo "[-] Wrong syntax!"
	echo "Usage example: sudo ./nmapscan.sh 10.10.10.1"
	exit 1
else
	echo "[+] Target: $1"
fi

#Get todays date, will use in filename
DATE=`date +%m-%d`
filename=$1_$DATE

#Port scan all ports, exports a nmap and port.txt file
echo ""
echo "[+] Running 0-65535 port scan..."
nmap -p 0-65535 --min-rate=1000 -T4 $1 -o portscan-$filename| grep ^[0-9] | cut -d "/" -f 1 | tr "\n" "," | sed s/,$// > ports.txt

#Presenting open ports
echo ""
echo "[+] Following ports are open:"
ports="$(cat ports.txt)"

if [[ "$ports" -eq 0 ]] ; then
	echo "[-] No ports found. Try to run script using sudo OR add -Pn to nmap scans on this script."
	echo "Usage example: sudo ./nmapscan.sh $1"
	exit 1
else
	echo "$(cat ports.txt)"
fi

#Recommendation
echo ""
echo "[+] Suggestions"

if [[ "$ports" == *"80"* || "$ports" = *"8080"* ]] ; then
	echo "===Port 80/8080 (HTTP)==="
	echo "[Suggest] Force Browse using gobuster:"
    echo "sudo gobuster dir -u http://$1:80/ -w /opt/SecLists/Discovery/Web-Content/common.txt"
    echo "sudo gobuster dir -u http://$1:80/ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -x html,php,txt"
    echo "[Suggest] SQLi: (Capture request (burp) that may be vulnerable to SQLi and use)" 
    echo "sqlmap -r login.req --batch"
    echo "[Suggest] Nikto VulnScan:"
    echo "nikto -h http://$1/"
fi

if [[ "$ports" == *"443"* ]] ; then
	echo "===Port 443 (HTTPS)==="
	echo "[Suggest] Force Browse using gobuster (use -k to skip TLS verification check):"
    echo "sudo gobuster dir -u https://$1/ -w /opt/SecLists/Discovery/Web-Content/common.txt"
	echo "sudo gobuster dir -u https://$1/ -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -x html,php,txt"
	echo "[Suggest] Look over SSL certificate:"
	echo "openssl s_client -connect $1:443 -showcerts"
	echo "[Suggest] Look over SAN certificate:"
	echo "openssl s_client -connect $1:443 | openssl x509 -noout -text | grep DNS:"
fi

if [[ "$ports" == *"119"* ]] ; then
	echo "===Port 119 (NNTP)==="
	echo "[Suggest] Use Netcat to interact:"
	echo "nc -nvC $1 119"
fi

if [[ "$ports" == *"139"* || "$ports" = *"445"* ]] ; then
	echo "===Port 139/445 (SMB)==="
	echo "[Suggest] Enumerate SMB using nmap:"
	echo "sudo nmap -sV --script smb-enum* -p 139,445 $1//"
	echo "[Suggest] Use smbclient to list shares:"
	echo "smbclient -N -L //$1//"
	echo "[Suggest] Use smbmap to list shares:"
	echo "smbmap -H $1"
	echo "[Suggest] NULL session:"
	echo "rpcclient -U \" \" -N $1"
    echo "[Suggest] Show open NFS shares:"
    echo "showmount -e $1"
	echo "[Suggest] Nmap script to enumerate SMB Shares and Users:"
	echo "nmap -p 139,445 -T4 --script=smb-enum-shares.nse,smb-enum-users.nse $1"
    echo "[Suggest] Mount a share locally:"
    echo "sudo mount -o vers=2 -t nfs $1:/sharename localfoldername"
fi

if [[ "$ports" == *"8009"* ]] ; then
	echo "===Port 8009 (Apache Jserv)==="
	echo "[Suggest] Check for GhostCat exploit:"
	echo "git clone https://github.com/00theway/Ghostcat-CNVD-2020-10487"
	echo "python3 ajpShooter.py http://$1:8080/ 8009 /blog/home.jsp read"
fi

if [[ "$ports" == *"1521"* ]] ; then
	echo "===Port 1521 (Oracle TNS Listener)==="
	echo "[Suggest] Use okcli to check log into Oracle DB"
	echo "okcli DBSNMP/DBSNMP@$1 -p 1521"
	echo "Find default credentials here: https://book.hacktricks.xyz/pentesting/1521-1522-1529-pentesting-oracle-listener#default-passwords"
fi

#Default Script and Version Scan against open ports
echo ""
echo "[+] Running Default Scripts and Version scan on open ports:"
echo ""
nmap -T4 -sV -sC -p $ports $1 -o scriptscan-$filename

echo ""
echo "[Suggest] Running Vuln Script Nmap Scan:"
echo "nmap -T4 -sV --script vuln -p $ports $1 -o vulnscan-$filename"

#Clean up
rm ports.txt
exit 0
