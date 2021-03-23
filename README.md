# Scripts

## UNIX Password Cracker
Pasword cracker created from following Violent Python.

## NmapScan
This bash script performs a TCP nmap scans against a given IP or hostname for all ports (0-65535) then runs a version scan and default scripts scan against open ports (-sV -sC). Each scan will be output their own nmap results (-o). Per my learnings, it will also post suggested tools to run for further enumeration.

Usage: `sudo ./nmapscan.sh 10.0.0.1`

 ![nmapscan example](example.png)

## More to come