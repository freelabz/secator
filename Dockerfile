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
	proxychains-ng

# Install Metasploit framework
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
RUN chmod 755 msfinstall
RUN ./msfinstall

# Copy code
WORKDIR /code
COPY . /code/

# Install secator
RUN pipx install .
RUN secator install tools
RUN secator install addons worker
RUN secator install addons google
RUN secator install addons mongodb
RUN secator install addons redis
RUN secator install addons dev

# Cleanup
RUN rm -rf /var/lib/apt/lists/*

# Set entrypoint
ENTRYPOINT ["secator"]