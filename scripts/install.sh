#!/bin/bash
YELLOW='\033[0;93m'
GREEN='\033[0;92m'
NC='\033[0m' # No Color

echo -e "🗄 ${YELLOW}Installing pipx ...${NC}"
sudo apt install pipx
echo -e "🗄 ${GREEN}pipx installed successfully !${NC}\n"

echo -e "🗄 ${YELLOW}Installing secator ...${NC}"
pipx install secator
echo -e "🗄 ${GREEN}secator installed successfully !${NC}\n"

secator install lang go
secator install lang ruby
secator install tools

echo -e "🗄 ${YELLOW}Adding ~/go/bin and ~/.local/bin to .bashrc ...${NC}"
echo "export PATH=$PATH:~/go/bin:~/.local/bin" >> ~/.bashrc
source ~/.bashrc
echo -e "🗄 ${GREEN}PATH modified successfully !${NC}\n"
