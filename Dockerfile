FROM ubuntu:20.04

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV GOROOT="/usr/local/go"
ENV GOPATH=$HOME/go
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin"

# Install Python
RUN apt update -y && \
    apt install -y software-properties-common && \
    add-apt-repository -y ppa:deadsnakes/ppa && \
    apt update -y && \
    apt install -y \
    libpcap-dev \
    python3.10 \
    python3-dev \
    python3-pip \
    wget

# Download and install go 1.19
RUN wget https://golang.org/dl/go1.19.5.linux-amd64.tar.gz
RUN tar -xvf go1.19.5.linux-amd64.tar.gz
RUN rm go1.19.5.linux-amd64.tar.gz
RUN mv go /usr/local

# Install Go tools
RUN go install -v github.com/edoardottt/cariddi/cmd/cariddi@latest
RUN go install -v github.com/ffuf/ffuf@latest
# RUN go install -v github.com/hakluke/hakrawler@latest
RUN go install -v github.com/jaeles-project/gospider@latest
RUN go install -v github.com/lc/gau/v2/cmd/gau@latest
# RUN go install -v github.com/OWASP/Amass/v3/...@latest
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install -v github.com/tomnomnom/gf@latest
# RUN go install -v github.com/tomnomnom/unfurl@latest
# RUN go install -v github.com/tomnomnom/waybackurls@latest

# Install nmap + vulscan
RUN apt install -y nmap
RUN git clone https://github.com/scipag/vulscan /usr/local/src/vulscan
RUN ln -s /usr/local/src/vulscan /usr/share/nmap/scripts/vulscan

# Install metasploit
RUN apt install -y \
    gpgv2 \
    autoconf \
    bison \
    build-essential \
    postgresql \
    libaprutil1 \
    libgmp3-dev \
    libpcap-dev \
    openssl \
    libpq-dev \
    libreadline6-dev \
    libsqlite3-dev \
    libssl-dev \
    locate \
    libsvn1 \
    libtool \
    libxml2 \
    libxml2-dev \
    libxslt-dev \
    wget \
    libyaml-dev \
    ncurses-dev \
    postgresql-contrib \
    xsel \
    zlib1g \
    zlib1g-dev
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
RUN chmod 755 msfinstall
RUN ./msfinstall

# Download wordlists
RUN mkdir -p /usr/src/wordlist
RUN wget https://raw.githubusercontent.com/maurosoria/dirsearch/master/db/dicc.txt -O /usr/src/wordlist/dicc.txt

# Install test and dev deps
RUN pip3 install free-proxy tldextract

# Copy code
WORKDIR /code
COPY . /code/

# Install Python package and CLI
RUN python3 setup.py develop