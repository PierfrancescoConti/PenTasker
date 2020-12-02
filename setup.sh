#!/bin/bash

mkdir tools
cd tools

echo -e '\n\n\033[37;1m\033[44;1m             Starting installation             \033[0m\n'

echo -e '\n\033[34;1m Cleaning... \033[0m\n'
rm -rf ./*
echo -e "\033[32;1m Done, let's start!\033[0m\n"


echo -e '\n\n\033[34;1m Obtaining tools... I need sudo\033[0m\n'
sudo apt install nmap -y
sudo apt install nikto -y
sudo apt install python2 -y
sudo apt install python3 -y
sudo apt install python3-tk -y
wget https://bootstrap.pypa.io/get-pip.py
python2 get-pip.py
python3 get-pip.py
pip install requests
python3 -m pip install requests
python3 -m pip install pysimplegui
python3 -m pip install python-docx
rm get-pip.py

git clone https://github.com/scipag/vulscan.git
git clone https://github.com/PierfrancescoConti/LiteRespH.git
git clone https://github.com/maurosoria/dirsearch.git
git clone https://github.com/drwetter/testssl.sh.git
git clone https://github.com/RedHatOfficial/rhsecapi.git
git clone https://github.com/irsdl/IIS-ShortName-Scanner.git
git clone https://github.com/carlospolop/legion.git

touch ~/.rhsecapi-no-argcomplete

echo -e '\n\033[32;1m Cloned repositories! \033[0m\n'
echo -e '\n\033[32;1m Installing legion and its tools...\033[0m\n'

cd legion/git
chmod +x install.sh
sudo ./install.sh
cd ../..

echo -e '\n\033[32;1m OK - tools are ready!\033[0m\n'




echo -e '\n\n\033[34;1m Updating VulnDB databases...\033[0m\n'

cd ..
cp updateFiles.sh tools/vulscan/utilities/updater/updateFiles.sh
cd tools/vulscan/utilities/updater/
chmod +x updateFiles.sh
./updateFiles.sh
cd ../../..
sudo ln -s `pwd`/vulscan /usr/share/nmap/scripts/vulscan


echo -e '\n\033[32;1m All is done!\033[0m\n'

echo -e '\n\n\033[37;1m\033[44;1m                      End                      \033[0m\n'

