#!/bin/bash

# gf
go install -v github.com/tomnomnom/gf@latest || true

# cariddi
go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest || true

# dirsearch
pip3 install dirsearch || true

# feroxbuster
sudo apt install -y unzip && curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash && sudo mv feroxbuster /usr/local/bin || true

# ffuf
go install -v github.com/ffuf/ffuf@latest && sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists || true

# gau
go install -v github.com/lc/gau/v2/cmd/gau@latest || true

# gospider
go install -v github.com/jaeles-project/gospider@latest || true

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true

# katana
go install -v github.com/projectdiscovery/katana/cmd/katana@latest || true

# fping
sudo apt install -y fping || true

# maigret
pip3 install maigret || true

# mapcidr
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest || true

# naabu
sudo apt install -y libpcap-dev && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true

# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true

# dalfox
go install -v github.com/hahwul/dalfox/v2@latest || true

# grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin || true

# nmap
sudo apt install -y nmap && sudo git clone https://github.com/scipag/vulscan /opt/scipag_vulscan && sudo ln -s /opt/scipag_vulscan /usr/share/nmap/scripts/vulscan || true

# nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || true

