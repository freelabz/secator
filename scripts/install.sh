#!/bin/bash

git clone https://github.com/freelabz/secsy-cli
cd secsy-cli
./scripts/install_go.sh
./scripts/install_commands.sh
pip3 install virtualenv
virtualenv ~/.secsy/venv
source ~/.secsy/venv/bin/activate
pip3 install -r requirements.txt
pip3 install -e .
