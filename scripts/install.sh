#!/bin/bash

./scripts/install_go.sh
./scripts/install_ruby.sh
./scripts/install_commands.sh
sudo apt install pipx
pipx install secator
echo "export PATH=$PATH:~/go/bin:~/.local/bin" >> ~/.bashrc
source ~/.bashrc