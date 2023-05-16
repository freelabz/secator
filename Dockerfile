FROM kalilinux/kali-rolling

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV GOROOT="/usr/local/go"
ENV GOPATH=$HOME/go
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin"

# Install Python
RUN apt update -y && \
    apt install -y \
	software-properties-common \
    curl \
	gcc \
    git \
    make \
	sudo \
	vim \
    wget \
    zlib1g \
    zlib1g-dev \
	libc6-dev \
	libgdbm-dev \
	libbz2-dev \
	libffi-dev \
	libreadline-dev \
	libncursesw5-dev \
	libsqlite3-dev \
	libssl-dev \
	tk-dev
RUN wget https://www.python.org/ftp/python/3.10.2/Python-3.10.2.tgz
RUN tar xvf Python-3.10.2.tgz && cd Python-3.10.2/ && ./configure --enable-optimizations && make && make install

# Install additional tools
RUN apt update -y && \
	apt install -y \
	chromium \
    jq \
    openssl \
	proxychains \
	proxychains-ng

# Install Metasploit framework
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
RUN chmod 755 msfinstall
RUN ./msfinstall

# Copy code
WORKDIR /code

# Download CVEs
# COPY scripts/download_cves.sh .
# RUN ./download_cves.sh

# Download and install go 1.19
COPY scripts/install_go.sh .
RUN ./install_go.sh
ENV PATH="$PATH:/root/go/bin"

# Install secsy tasks
COPY scripts/install_commands.sh .
RUN ./install_commands.sh

# Install Python package and CLI
COPY requirements.txt .
RUN pip3 install wheel
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy rest of the code
COPY . /code/

# Install secsy
RUN pip3 uninstall httpx
RUN pip3 install --no-deps -e .

# Set entrypoint
ENTRYPOINT ["secsy"]