FROM kalilinux/kali-rolling

ENV PATH="${PATH}:/root/go/bin:/root/.local/bin"

# Install Python
# RUN apt update -y && \
#     apt install -y \
# 	software-properties-common \
#     curl \
# 	gcc \
#     git \
# 	golang-go \
#     make \
# 	python3 \
# 	python3-pip \
# 	python3-venv \
# 	ruby \
# 	sudo \
# 	vim \
#     wget \
#     zlib1g \
#     zlib1g-dev \
# 	libc6-dev \
# 	libgdbm-dev \
# 	libbz2-dev \
# 	libffi-dev \
# 	libreadline-dev \
# 	libncursesw5-dev \
# 	libsqlite3-dev \
# 	libssl-dev \
# 	tk-dev \
# 	chromium \
#     jq \
#     openssl \
# 	proxychains \
# 	proxychains-ng \
# 	&& rm -rf /var/lib/apt/lists/*

RUN apt update -y && \
    apt install -y \
	curl \
	git \
	golang-go \
    make \
	pipx \
	python3 \
	python3-pip \
	python3-venv \
	ruby \
	sudo \
	vim \
    wget \
	chromium \
    jq \
    openssl \
	proxychains \
	proxychains-ng \
	&& rm -rf /var/lib/apt/lists/*

# Install Metasploit framework
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
RUN chmod 755 msfinstall
RUN ./msfinstall

# Copy code
WORKDIR /code
COPY . /code/

# Install secator
RUN pipx install .[dev,google]
RUN secator install tools

# Set entrypoint
ENTRYPOINT ["secator"]