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
    curl \
    git \
    sudo \
    wget

# Install metasploit
RUN apt install -y \
    gcc \
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

# Download and install go 1.19
RUN wget https://golang.org/dl/go1.20.2.linux-amd64.tar.gz
RUN tar -xvf go1.20.2.linux-amd64.tar.gz
RUN rm go1.20.2.linux-amd64.tar.gz
RUN mv go /usr/local

# Copy code
WORKDIR /code

# Install secsy tasks
COPY scripts/install.sh .
RUN ./install.sh

# Install Python package and CLI
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy rest of the code
COPY . /code/

# Install secsy
RUN pip3 install --no-deps .

# Set entrypoint
ENTRYPOINT ["secsy"]