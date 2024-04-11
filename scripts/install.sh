#!/bin/bash
YELLOW='\033[0;93m'
GREEN='\033[0;92m'
NC='\033[0m' # No Color

echo -e "🗄 ${YELLOW}Running apt update ...${NC}"
sudo apt update
echo -e "🗄 ${GREEN}Ran apt update successfully !${NC}\n"

echo -e "🗄 ${YELLOW}Installing pipx and git ...${NC}"
sudo apt install -y pipx git
echo -e "🗄 ${GREEN}pipx and git installed successfully !${NC}\n"

echo -e "🗄 ${YELLOW}Setting \$PATH ...${NC}"
export PATH=$PATH:~/.local/bin:~/go/bin
echo -e "🗄 ${GREEN}\$PATH modified successfully !${NC}\n"

echo -e "🗄 ${YELLOW}Installing secator and dependencies ...${NC}"
pipx install secator
secator install langs go
secator install langs ruby
secator install tools
secator install addons redis
secator install addons worker
secator install addons google
secator install addons mongodb
echo -e "🗄 ${GREEN}secator installed successfully !${NC}\n"

echo -e "🗄 ${YELLOW}Adding ~/go/bin and ~/.local/bin to \$PATH in .bashrc ...${NC}"
echo "export PATH=$PATH:~/go/bin:~/.local/bin" >> ~/.bashrc
. ~/.bashrc
echo -e "🗄 ${GREEN}\$PATH modified successfully !${NC}\n"
