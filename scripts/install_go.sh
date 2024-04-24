#!/bin/bash
GO_VERSION=1.22.0
GO_BUILD=linux-amd64.tar.gz
GO_TAR=go$GO_VERSION.$GO_BUILD

YELLOW='\033[0;93m'
GREEN='\033[0;92m'
NC='\033[0m' # No Color

echo -e "🗄 ${YELLOW}Downloading Go $GO_VERSION ...${NC}"
wget https://golang.org/dl/$GO_TAR

echo -e "🗄 ${YELLOW}Unzip $GO_TAR ...${NC}"
tar -xvf $GO_TAR
rm $GO_TAR || true

echo -e "🗄 ${YELLOW}Linking Go install to /usr/local ...${NC}"
sudo mv go /usr/local/go$GO_VERSION
sudo mv /usr/bin/go /usr/bin/go.bak || true
sudo ln -s /usr/local/go$GO_VERSION/bin/go /usr/bin/go

echo -e "🗄 ${GREEN}Go $GO_VERSION installed successfully !${NC}\n"
