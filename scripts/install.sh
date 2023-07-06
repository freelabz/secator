#!/bin/bash

git clone https://github.com/freelabz/secator
cd secator
./scripts/install_go.sh
./scripts/install_ruby.sh
./scripts/install_commands.sh
pip3 install virtualenv
virtualenv ~/.secator/venv
echo "export PATH=$PATH:~/go/bin:~/.local/bin" >> ~/.bashrc
echo "source ~/.secator/venv/bin/activate" >> ~/.bashrc
source ~/.bashrc
pip3 install -r requirements.txt
pip3 install -e .
