wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
apt update
apt upgrade
apt install -y nmap proxychains sshuttle pipx snapd python3-pip python3-venv python3-poetry xfce4 xfce4-goodies xfce4-settings tightvncserver apt-transport-https sublime-text golang hydra dnsrecon dnsenum smbmap ruby-dev terminator
# mv /usr/lib/python3.11/EXTERNALLY-MANAGED /usr/lib/python3.11/EXTERNALLY-MANAGED.old # Fix if getting externally-managed-environment error
#If on Ubuntu uncomment 3 below
#snap install metasploit-framework # otherwise follow https://docs.rapid7.com/metasploit/installing-the-metasploit-framework/#installing-the-metasploit-framework-on-linux
#snap install evil-winrm # otherwise gem install evil-winrm
pip3 install pyftpdlib setuptools colorama termcolor service_identity ldap3 hydra-core droopescan
pipx install impacket crackmapexec
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest
export PATH=$PATH:$(go env GOPATH)/bin
mkdir /opt/seclist
mkdir /opt/scripts
current_build=$(curl -s https://github.com/peass-ng/PEASS-ng/releases | grep -i "refs/heads/master" -m 1 | awk '{ print $5 }' | cut -d "<" -f1)
releases_url="https://github.com/peass-ng/PEASS-ng/releases/download/$current_build"
wget -q $releases_url/linpeas.sh -O /opt/scripts/linpeas.sh
wget -q $releases_url/winPEASany.exe  -O /opt/scripts/winPEASany.exe
wget https://github.com/danielmiessler/SecLists/archive/master.zip -O /tmp/SecList.zip
unzip -o /tmp/SecList.zip -d /opt/seclist
rm -f /tmp/SecList.zip
vncserver -localhost
vncserver -kill :1
# Edit vncserver per https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-vnc-on-ubuntu-20-04
wget 'https://portswigger-cdn.net/burp/releases/download?product=community&version=2024.2.1.3&type=Linux' -O burp_community_install.sh
# If have license switch above to ?product=pro&version=2024.2.1.3&type=Linux
bash burp_community_install.sh
