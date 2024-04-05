wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null
echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list
apt update
apt upgrade
apt install -y nmap proxychains sshuttle pipx snapd python3-pip python3-venv python3-poetry xfce4 xfce4-goodies xfce4-settings tightvncserver apt-transport-https sublime-text golang hydra dnsrecon dnsenum smbmap droopescan ruby-dev ruby-rubygem
rm /usr/lib/python3.11/EXTERNALLY-MANAGED
snap install metasploit-framework
snap install evil-winrm
pip3 install pyftpdlib setuptools colorama termcolor service_identity ldap3 kerbrute hydra-core
pipx install impacket
go install github.com/OJ/gobuster/v3@latest
go install github.com/ffuf/ffuf/v2@latest
export PATH=$PATH:$(go env GOPATH)/bin
snap install crackmapexec
mkdir /opt/seclist
mkdir /opt/scripts
current_build=$(curl -s https://github.com/carlospolop/PEASS-ng/releases | grep -i "refs/heads/master" -m 1 | awk '{ print $5 }' | cut -d "<" -f1)
releases_url="https://github.com/carlospolop/PEASS-ng/releases/download/$current_build"
wget -q $releases_url/linpeas.sh -O /opt/scripts/linpeas.sh
wget -q $releases_url/winPEASany.exe  -O /opt/scripts/winPEASany.exe
wget https://github.com/danielmiessler/SecLists/archive/master.zip -O /tmp/SecList.zip
unzip -o /tmp/SecList.zip -d /opt/seclist
rm -f /tmp/SecList.zip
vncserver -localhost
vncserver -kill :1
# Edit vncserver per https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-vnc-on-ubuntu-20-04
