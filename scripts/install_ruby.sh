#!/bin/bash
YELLOW='\033[0;93m'
GREEN='\033[0;92m'
NC='\033[0m' # No Color

echo -e "🗄 ${YELLOW}Installing Ruby ...${NC}"
sudo apt update -y
sudo apt install -y ruby-full
sudo apt install -y rubygems

echo -e "🗄 ${GREEN}Ruby installed successfully !${NC}\n"
