#!/bin/bash

mkdir tools
cd tools

echo -e '\n\n\033[37;1m\033[44;1m             Starting installation             \033[0m\n'

echo -e '\n\033[34;1m Cleaning... \033[0m\n'
rm -rf ./*
echo -e "\033[32;1m Done, let's start!\033[0m\n"


echo -e '\n\n\033[34;1m Obtaining tools...\033[0m\n'
sudo apt install nmap -y

git clone https://github.com/scipag/vulscan.git
git clone https://github.com/PierfrancescoConti/LiteRespH.git
git clone https://github.com/maurosoria/dirsearch.git
git clone https://github.com/drwetter/testssl.sh.git

echo -e '\n\033[32;1m Cloned repositories - tools are ready!\033[0m\n'




echo -e '\n\n\033[34;1m Updating VulnDB databases...\033[0m\n'

cd ..
cp updateFiles.sh tools/vulscan/utilities/updater/updateFiles.sh
cd tools/vulscan/utilities/updater/
chmod +x updateFiles.sh
./updateFiles.sh

echo -e '\n\033[32;1m For those I need sudo \033[0m\n'

sudo apt install nmap -y
sudo apt install python3 -y
sudo apt install python3-tk -y


echo -e '\n\033[32;1m All is done!\033[0m\n'

echo -e '\n\n\033[37;1m\033[44;1m                      End                      \033[0m\n'

