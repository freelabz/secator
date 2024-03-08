#!/bin/bash

# searchsploit
echo -e "
🗄 \033[0;93mInstalling searchsploit ...\033[0m"
echo -e "\033[0;96msudo snap install searchsploit\033[0m"
sudo snap install searchsploit || true

# httpx
echo -e "
🗄 \033[0;93mInstalling httpx ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/projectdiscovery/httpx/cmd/httpx@latest\033[0m"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || true

# cariddi
echo -e "
🗄 \033[0;93mInstalling cariddi ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/edoardottt/cariddi/cmd/cariddi@latest\033[0m"
go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest || true

# gau
echo -e "
🗄 \033[0;93mInstalling gau ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/lc/gau/v2/cmd/gau@latest\033[0m"
go install -v github.com/lc/gau/v2/cmd/gau@latest || true

# gospider
echo -e "
🗄 \033[0;93mInstalling gospider ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/jaeles-project/gospider@latest\033[0m"
go install -v github.com/jaeles-project/gospider@latest || true

# katana
echo -e "
🗄 \033[0;93mInstalling katana ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/projectdiscovery/katana/cmd/katana@latest\033[0m"
go install -v github.com/projectdiscovery/katana/cmd/katana@latest || true

# dirsearch
echo -e "
🗄 \033[0;93mInstalling dirsearch ...\033[0m"
echo -e "\033[0;96mpipx install dirsearch\033[0m"
pipx install dirsearch || true

# feroxbuster
echo -e "
🗄 \033[0;93mInstalling feroxbuster ...\033[0m"
echo -e "\033[0;96msudo apt install -y unzip curl && curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash && sudo mv feroxbuster /usr/local/bin\033[0m"
sudo apt install -y unzip curl && curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/master/install-nix.sh | bash && sudo mv feroxbuster /usr/local/bin || true

# ffuf
echo -e "
🗄 \033[0;93mInstalling ffuf ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/ffuf/ffuf@latest && sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists || true\033[0m"
go install -v github.com/ffuf/ffuf@latest && sudo git clone https://github.com/danielmiessler/SecLists /usr/share/seclists || true || true

# h8mail
echo -e "
🗄 \033[0;93mInstalling h8mail ...\033[0m"
echo -e "\033[0;96mpipx install h8mail\033[0m"
pipx install h8mail || true

# dnsx
echo -e "
🗄 \033[0;93mInstalling dnsx ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest\033[0m"
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true

# dnsxbrute
echo -e "
🗄 \033[0;93mInstalling dnsxbrute ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest\033[0m"
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest || true

# subfinder
echo -e "
🗄 \033[0;93mInstalling subfinder ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\033[0m"
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true

# fping
echo -e "
🗄 \033[0;93mInstalling fping ...\033[0m"
echo -e "\033[0;96msudo apt install -y fping\033[0m"
sudo apt install -y fping || true

# mapcidr
echo -e "
🗄 \033[0;93mInstalling mapcidr ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest\033[0m"
go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest || true

# naabu
echo -e "
🗄 \033[0;93mInstalling naabu ...\033[0m"
echo -e "\033[0;96msudo apt install -y libpcap-dev && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest\033[0m"
sudo apt install -y libpcap-dev && go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest || true

# maigret
echo -e "
🗄 \033[0;93mInstalling maigret ...\033[0m"
echo -e "\033[0;96mpipx install maigret\033[0m"
pipx install maigret || true

# gf
echo -e "
🗄 \033[0;93mInstalling gf ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns $HOME/.gf || true\033[0m"
go install -v github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns $HOME/.gf || true || true

# grype
echo -e "
🗄 \033[0;93mInstalling grype ...\033[0m"
echo -e "\033[0;96mcurl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin\033[0m"
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin || true

# dalfox
echo -e "
🗄 \033[0;93mInstalling dalfox ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/hahwul/dalfox/v2@latest\033[0m"
go install -v github.com/hahwul/dalfox/v2@latest || true

# wpscan
echo -e "
🗄 \033[0;93mInstalling wpscan ...\033[0m"
echo -e "\033[0;96msudo gem install wpscan\033[0m"
sudo gem install wpscan || true

# nmap
echo -e "
🗄 \033[0;93mInstalling nmap ...\033[0m"
echo -e "\033[0;96msudo apt install -y nmap && sudo git clone https://github.com/scipag/vulscan /opt/scipag_vulscan || true && sudo ln -s /opt/scipag_vulscan /usr/share/nmap/scripts/vulscan || true\033[0m"
sudo apt install -y nmap && sudo git clone https://github.com/scipag/vulscan /opt/scipag_vulscan || true && sudo ln -s /opt/scipag_vulscan /usr/share/nmap/scripts/vulscan || true || true

# nuclei
echo -e "
🗄 \033[0;93mInstalling nuclei ...\033[0m"
echo -e "\033[0;96mgo install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest\033[0m"
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || true

