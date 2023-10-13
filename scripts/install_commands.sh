#!/bin/bash

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true

# cariddi
go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest || true

# gau
go install -v github.com/lc/gau/v2/cmd/gau@latest || true

# gospider
go install -v github.com/jaeles-project/gospider@latest || true

# katana
go install -v github.com/projectdiscovery/katana/cmd/katana@latest || true

# dirsearch
pip3 install dirsearch || true

# feroxbuster
sudo apt install -y unzip && curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash && sudo mv feroxbuster /usr/local/bin || true

# ffuf
go install -v github.com/ffuf/ffuf@latest && sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists || true || true

# h8mail
pip3 install h8mail || true

# dnsx
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true

# dnsxbrute
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true

# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true

# fping
sudo apt install -y fping || true

# mapcidr
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest || true

# naabu
sudo apt install -y libpcap-dev && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true

# maigret
pip3 install maigret || true

# gf
go install -v github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns $HOME/.gf || true || true

# grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin || true

# dalfox
go install -v github.com/hahwul/dalfox/v2@latest || true

# wpscan
sudo gem install wpscan || true

# nmap
sudo apt install -y nmap && sudo git clone https://github.com/scipag/vulscan /opt/scipag_vulscan || true && sudo ln -s /opt/scipag_vulscan /usr/share/nmap/scripts/vulscan || true || true

# nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || true

