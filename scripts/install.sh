#!/bin/bash

git clone https://github.com/freelabz/secsy-cli
cd secsy-cli
./scripts/install_go.sh
./scripts/install_commands.sh
pip3 install virtualenv
virtualenv ~/.secsy/venv
echo "export PATH=$PATH:~/.local/go/bin" >> ~/.bashrc
echo "source ~/.secsy/venv/bin/activate" >> ~/.bashrc
source ~/.bashrc
pip3 install -r requirements.txt
pip3 install -e .
