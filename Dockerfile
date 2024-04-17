FROM alpine:latest

ARG GITHUB_TOKEN

ENV PATH="${PATH}:/root/go/bin:/root/.local/bin"
ENV GITHUB_TOKEN=${GITHUB_TOKEN}

RUN apk add --no-cache \
	curl \
	freetype-dev \
	gcc \
	git \
	go \
	libc6-compat \
	libpcap-dev \
    make \
	pipx \
	python3-dev \
	ruby-dev \
	linux-headers \
	sudo \
	vim \
    wget \
	chromium \
    openssl \
	proxychains-ng

# Fix for https://github.com/projectdiscovery/naabu/discussions/238
RUN ln -s /usr/lib/libpcap.so /usr/lib/libpcap.so.0.8

# Install Metasploit framework
# RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
# RUN chmod 755 msfinstall
# RUN ./msfinstall

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

# Set entrypoint
ENTRYPOINT ["secator"]