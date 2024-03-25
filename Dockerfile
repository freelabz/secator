FROM kalilinux/kali-rolling

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1
ENV GOROOT="/usr/local/go"
ENV GOPATH=$HOME/go
ENV PATH="${PATH}:${GOROOT}/bin:${GOPATH}/bin:/root/.local/share/pipx/venvs/secator/bin:/root/go/bin"

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
RUN pip3 install pipx
RUN pip3 uninstall httpx

# Install Metasploit framework
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
RUN chmod 755 msfinstall
RUN ./msfinstall

# Copy code
WORKDIR /code
COPY . /code/

# Install secator
RUN pipx install .[dev,google]
RUN secator install go
RUN secator install ruby
RUN secator install tools

# Set entrypoint
ENTRYPOINT ["secator"]