FROM kalilinux/kali-rolling

ENV PATH="${PATH}:/root/go/bin:/root/.local/bin"

RUN apt update -y && \
    apt install -y \
	curl \
	gcc \
	git \
	golang-go \
    make \
	pipx \
	python3 \
	python3-pip \
	python3-venv \
	ruby-full \
	rubygems \
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